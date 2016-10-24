#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openflow/openflow.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include "config.h"
#include "cbench.h"
#include "fakeswitch.h"

#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif

static int debug_msg(struct fakeswitch * fs, char * msg, ...);
static int make_packet_in(int switch_id, int xid, int buffer_id, char * buf, int buflen, int mac_address);
static int make_features_reply(int switch_id, int xid, char * buf, int buflen);
static int make_stats_desc_reply(struct ofp_stats_request * req, char * buf, int buflen);
static int parse_set_config(struct ofp_header * msg);
static int make_config_reply( int xid, char * buf, int buflen);
static int make_vendor_reply(int xid, char * buf, int buflen);
static int packet_out_is_lldp(struct ofp_packet_out * po);
static void fakeswitch_handle_write(struct fakeswitch *fs);
void fakeswitch_change_status_now (struct fakeswitch *fs, int new_status);
void fakeswitch_change_status (struct fakeswitch *fs, int new_status);

static struct ofp_switch_config Switch_config = {
    .header = { OFP_VERSION, OFPT_GET_CONFIG_REPLY, sizeof(struct ofp_switch_config), 0},
    .flags = 0,
    .miss_send_len = 0,
};

static inline uint64_t htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

unsigned char* pcapbuf;
#define GLOBAL_HEADER 24
#define PACKET_HEADER 16

void fakeswitch_init(struct fakeswitch *fs, int dpid, int sock, int bufsize, int debug, int delay, enum test_mode mode, int total_mac_addresses, char* pcap_file)
{
    char buf[BUFLEN];
    struct ofp_header ofph;
    fs->sock = sock;
    fs->debug = debug;
    #ifdef USE_EPOLL
    fs->id = dpid;
    #else
    static int ID = 1;
    fs->id = ID++;
    #endif
    fs->inbuf = msgbuf_new(bufsize);
    fs->outbuf = msgbuf_new(bufsize);
    fs->probe_state = 0;
    fs->mode = mode;
    fprintf(stderr, "Current_mac_address: %d\n", fs->current_mac_address);
    //fs->probe_size = make_packet_in(fs->id, 0, 0, buf, BUFLEN, fs->current_mac_address++);
    fs->count = 0;
    fs->switch_status = START;
    fs->delay = delay;
    fs->total_mac_addresses = total_mac_addresses;
    fs->current_mac_address = 0;
    fs->xid = 1;
    //fs->learn_dstmac = learn_dstmac;
    fs->current_buffer_id = 1;

    // read pcap file into a buffer
    FILE *f = fopen(pcap_file, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    pcapbuf = malloc(fsize + 1);
    fread(pcapbuf, fsize, 1, f);
    fclose(f);
    pcapbuf[fsize] = 0;    
    // print the global header
    int i, n=24;
    if(fs->debug)
    {
        fprintf(stderr, "pcap global header ...\n");
        for(i=0; i<n; i++)
            fprintf(stderr, "%02x ", pcapbuf[i]);
        printf("\n");
    }
    // skip the global header
    pcapbuf = &pcapbuf[GLOBAL_HEADER];

    ofph.version = OFP_VERSION;
    ofph.type = OFPT_HELLO;
    ofph.length = htons(sizeof(ofph));
    ofph.xid   = htonl(1);

    // Send HELLO
    msgbuf_push(fs->outbuf,(char * ) &ofph, sizeof(ofph));
    debug_msg(fs, " sent hello");
}

/***********************************************************************/
void fakeswitch_change_status_now(struct fakeswitch *fs, int new_status){
    fs->switch_status = new_status;
    if(new_status == READY_TO_SEND){
        fs->count = 0;
        fs->probe_state = 0;
    }
}

void fakeswitch_change_status(struct fakeswitch *fs, int new_status) {
    if( fs->delay == 0) {
        fakeswitch_change_status_now(fs, new_status);
        debug_msg(fs, " switched to next status %d", new_status);
    } else {
        fs->switch_status = WAITING;
        fs->next_status = new_status;
        gettimeofday(&fs->delay_start, NULL);
        fs->delay_start.tv_sec += fs->delay / 1000;
        fs->delay_start.tv_usec += (fs->delay % 1000 ) * 1000;
        debug_msg(fs, " delaying next status %d by %d ms", new_status, fs->delay);
    }
}

/***********************************************************************/
static int make_vendor_reply(int xid, char * buf, int buflen)
{
    struct ofp_error_msg * e;
    assert(buflen> sizeof(struct ofp_error_msg));
    e = (struct ofp_error_msg *) buf;
    e->header.type = OFPT_ERROR;
    e->header.version = OFP_VERSION;
    e->header.length = htons(sizeof(struct ofp_error_msg));
    e->header.xid = xid;
    e->type = htons(OFPET_BAD_REQUEST);
    e->code = htons(OFPBRC_BAD_VENDOR);
    return sizeof(struct ofp_error_msg);
}

/***********************************************************************/
static int parse_set_config(struct ofp_header * msg) {
    struct ofp_switch_config * sc;
    assert(msg->type == OFPT_SET_CONFIG);
    sc = (struct ofp_switch_config *) msg;
    memcpy(&Switch_config, sc, sizeof(struct ofp_switch_config));

    return 0;
}

/***********************************************************************/
static int make_config_reply( int xid, char * buf, int buflen) {
    int len = sizeof(struct ofp_switch_config);
    assert(buflen >= len);
    Switch_config.header.type = OFPT_GET_CONFIG_REPLY;
    Switch_config.header.xid = xid;
    memcpy(buf, &Switch_config, len);

    return len;
}

/***********************************************************************/
static int              make_features_reply(int id, int xid, char * buf, int buflen)
{
    struct ofp_switch_features * features;
    const char fake[] =     // stolen from wireshark
    {

      0x97,0x06,0x00,0xe0,0x04,0x01,0x00,0x00,0x00,0x00,0x76,0xa9,
      0xd4,0x0d,0x25,0x48,0x00,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x07,0xff,0x00,0x01,0x1a,0xc1,0x51,0xff,0xef,0x8a,0x76,0x65,0x74,0x68,
      0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x02,0xce,0x2f,0xa2,0x87,0xf6,0x70,0x76,0x65,0x74,0x68,
      0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x03,0xca,0x8a,0x1e,0xf3,0x77,0xef,0x76,0x65,0x74,0x68,
      0x35,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x04,0xfa,0xbc,0x77,0x8d,0x7e,0x0b,0x76,0x65,0x74,0x68,
      0x37,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00
    };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    features = (struct ofp_switch_features *) buf;
    features->header.version = OFP_VERSION;
    features->header.xid = xid;
    features->datapath_id = htonll(id);
    return sizeof(fake);
}
/***********************************************************************/
static int make_packet_in(int switch_id, int xid, int buffer_id, char* buf, int buflen, int mac_address)
{
    struct ofp_packet_in *pi;
    const char fake[] = {               
        0x97,0x0a,0x00,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x01,0x00,0x40,0x00,0x01,0x00,0x00};
    assert(buflen > sizeof(fake));
    memcpy(buf, fake, sizeof(fake));

    //For debug use only
    #if 0 
    int i;
    for(i=0; i<sizeof(fake); i++){
        fprintf(stderr, "%02x ", (unsigned int)buf[i]);
    }
    fprintf(stderr, "\n"); 
    pi = (struct ofp_packet_in *) buf;
    pi->header.version = OFP_VERSION;
    pi->header.length = htons(sizeof(fake));
    pi->header.xid = htonl(xid);
    pi->buffer_id = htonl(buffer_id);
    pi->total_len = htons(0);
    
    for(i=0; i<sizeof(fake); i++){
        fprintf(stderr, "%02x ", (unsigned int)buf[i]);
    }
    fprintf(stderr, "\n");
    return sizeof(fake);
    #endif
    // include real packet from pcap-file
    unsigned int * p = (unsigned int *)pcapbuf;
    unsigned int packet_size = p[3];     //size of the saved packet data in file
    assert((buflen - sizeof(fake)) > packet_size);
    // skip 16-bytes packet_header
    pcapbuf = &pcapbuf[PACKET_HEADER];
    memcpy(&buf[sizeof(fake)], pcapbuf, packet_size);

    pi = (struct ofp_packet_in *) buf;
    pi->header.version = OFP_VERSION;
    pi->header.length = htons(sizeof(fake) + packet_size);
    pi->header.xid = htonl(xid);
    pi->buffer_id = htonl(buffer_id);
    pi->total_len = htons(packet_size);
    return sizeof(fake) + packet_size;
}     
#if 0
static int make_packet_in(int switch_id, int xid, int buffer_id, char * buf, int buflen, int mac_address)
{
    struct ofp_packet_in * pi;
    struct ether_header * eth;
    const char fake[] = {
                0x97,0x0a,0x00,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x01,0x00,0x40,0x00,0x01,0x00,0x00,0x80,0x00,0x00,0x00,
        0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x02,0x08,0x00,0x45,
        0x00,0x00,0x32,0x00,0x00,0x00,0x00,0x40,0xff,0xf7,0x2c,
        0xc0,0xa8,0x00,0x28,0xc0,0xa8,0x01,0x28,0x7a,0x18,0x58,
                0x6b,0x11,0x08,0x97,0xf5,0x19,0xe2,0x65,0x7e,0x07,0xcc,
                0x31,0xc3,0x11,0xc7,0xc4,0x0c,0x8b,0x95,0x51,0x51,0x33,
                0x54,0x51,0xd5,0x00,0x36};
    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    pi = (struct ofp_packet_in *) buf;
    pi->header.version = OFP_VERSION;
    pi->header.xid = htonl(xid);
    pi->buffer_id = htonl(buffer_id);

    eth = (struct ether_header * ) pi->data;
    // copy into src mac addr; only 4 bytes, but should suffice to not confuse
    // the controller; don't overwrite first byte
    memcpy(&eth->ether_shost[1], &mac_address, sizeof(mac_address));
    // mark this as coming from us, mostly for debug
    eth->ether_dhost[5] = switch_id;
    eth->ether_shost[5] = switch_id;
    return sizeof(fake);
}
#endif
/***********************************************************************/
void fakeswitch_handle_read(struct fakeswitch *fs)
{
    int count;
    struct ofp_header * ofph;
    struct ofp_header echo;
    struct ofp_header barrier;
    char buf[BUFLEN];
    count = msgbuf_read(fs->inbuf, fs->sock);   // read any queued data
    if (count <= 0)
    {
        fprintf(stderr, "controller msgbuf_read() = %d:  ", count);
        if(count < 0)
            perror("msgbuf_read");
        else
            fprintf(stderr, " closed connection ");
        fprintf(stderr, "... exiting\n");
        exit(1);
    }
    while((count= msgbuf_count_buffered(fs->inbuf)) >= sizeof(struct ofp_header ))
    {
        ofph = msgbuf_peek(fs->inbuf);
        if(count < ntohs(ofph->length))
            return;     // msg not all there yet
        msgbuf_pull(fs->inbuf, NULL, ntohs(ofph->length));
        switch(ofph->type)
        {
            struct ofp_flow_mod* fm;
            case OFPT_FLOW_MOD:
                debug_msg(fs, "got flow_mod response");
                fm = (struct ofp_flow_mod *) ofph;
                if(fs->switch_status == READY_TO_SEND){
                    fs->count++;
                    //fs->probe_state--;
                }
                break;
            case OFPT_HELLO:
                debug_msg(fs, "got hello");
                // we already sent out our own HELLO; don't respond
                break;
            case OFPT_ECHO_REQUEST:
                debug_msg(fs, "got echo, send echo_resp");
                echo.version = OFP_VERSION;
                echo.length = htons(sizeof(echo));
                echo.type = OFPT_ECHO_REPLY;
                echo.xid = ofph->xid;
                msgbuf_push(fs->outbuf, (char*) &echo, sizeof(echo));
                break;
            case OFPT_FEATURES_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got feature_req");
                // send features reply
                count = make_features_reply(fs->id, ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent feature_rsp");
                //fakeswitch_change_status_now(fs, READY_TO_SEND);
                break;
            case OFPT_SET_CONFIG:
                // pull msgs out of buffer
                debug_msg(fs, "parsing set_config");
                parse_set_config(ofph);
                break;
            case OFPT_GET_CONFIG_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got get_config_request");
                count = make_config_reply(ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                if ((fs->mode = MODE_LATENCY) && (fs->probe_state == 1)){
                    // restart probe state b/c some controllers block on config
                    fs->probe_state = 0;                       
                    debug_msg(fs, "reset probe state b/c of get_config_reply");
                }
                debug_msg(fs, "sent get_config_reply");
                break;
            case OFPT_VENDOR:
                // pull msgs out of buffer
                debug_msg(fs, "got vendor");
                count = make_vendor_reply(ofph->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent vendor");
                // apply nox hack; nox ignores packet_in until this msg is sent
                fs->probe_state = 0;
                break; 
            case OFPT_BARRIER_REQUEST:
                debug_msg(fs, "got barrier, sent barrier_resp");
                barrier.version= OFP_VERSION;
                barrier.length = htons(sizeof(barrier));
                barrier.type   = OFPT_BARRIER_REPLY;
                barrier.xid = ofph->xid;
                msgbuf_push(fs->outbuf,(char *) &barrier, sizeof(barrier));
                fakeswitch_change_status(fs, READY_TO_SEND);
                break;            
            default:
                fprintf(stderr, "Ignoring OpenFlow message type %d\n", ofph->type);
        };
        if(fs->probe_state < 0)
        {
            debug_msg(fs, "WARN: Got more responses than probes!!: : %d",
                    fs->probe_state);
            fs->probe_state = 0;
        }
    }
} 

/***********************************************************************/
static void fakeswitch_handle_write(struct fakeswitch *fs)
{
    char buf[BUFLEN];
    int count;
    int send_count = 0;
    int throughput_buffer = BUFLEN;
    int i;
    if(fs->switch_status == READY_TO_SEND)
    {
        if((fs->mode == MODE_LATENCY) && (fs->probe_state == 0)){
            // just send one packet
            send_count = 1;
            debug_msg(fs, "send one packet"); 
        }
        for(i=0; i < send_count; i++)
        {
            // queue up packet
            fs->probe_state++;
            count = make_packet_in(fs->id, fs->xid++, fs->current_buffer_id, buf, BUFLEN, fs->current_mac_address);
            //fs->current_mac_address = ( fs->current_mac_address + 1 ) % fs->total_mac_addresses;
            //fs->current_buffer_id =  ( fs->current_buffer_id + 1 ) % NUM_BUFFER_IDS;
            msgbuf_push(fs->outbuf, buf, count);
            debug_msg(fs, "send message %d: size %d", i, count);
        }
    } else if(fs->switch_status == WAITING)
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        if(timercmp(&now, &fs->delay_start, >))
        {
            fakeswitch_change_status_now(fs, fs->next_status);
            debug_msg(fs, " delay is over: switching to state %d", fs->next_status);
        }
    }     
    // send any data if it's queued
    if( msgbuf_count_buffered(fs->outbuf) > 0)
        msgbuf_write(fs->outbuf, fs->sock, 0);
}

/***********************************************************************/
void fakeswitch_handle_io(struct fakeswitch *fs, void *pfd_events)
{
    #ifdef USE_EPOLL
    int events = *((int*) pfd_events);
    if(events & EPOLLIN) {
        fakeswitch_handle_read(fs);
    } else if(events & EPOLLOUT) {
        fakeswitch_handle_write(fs);
    }
    #endif
}


/************************************************************************/
static int debug_msg(struct fakeswitch * fs, char * msg, ...)
{
    va_list aq;
    if(fs->debug == 0)
        return 0;
    fprintf(stderr,"\n-------Switch %d: ", fs->id);
    va_start(aq,msg);
    vfprintf(stderr,msg,aq);
    if(msg[strlen(msg)-1] != '\n')
        fprintf(stderr, "\n");
    return 1;
}

