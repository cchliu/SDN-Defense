#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/tcp.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <openflow/openflow.h>

#include "myargs.h"
#include "cbench.h"
#include "fakeswitch.h"

#ifdef USE_EPOLL
#include <sys/epoll.h>
#define MAX_EVENTS  16
struct epoll_event events[MAX_EVENTS];
int epollfd;
#endif

struct myargs my_options[] = {
    {"controller",  'c', "hostname of controller to connect to", MYARGS_STRING, {.string = "localhost"}},
    {"debug",       'd', "enable debugging", MYARGS_FLAG, {.flag = 0}},
    {"switches",    's', "fake $n switches", MYARGS_INTEGER, {.integer = 1}},
    {"port",        'p', "controller port",  MYARGS_INTEGER, {.integer = OFP_TCP_PORT}},
    {"mac-addresses", 'M', "unique source MAC addresses per switch", MYARGS_INTEGER, {.integer = 100000}},
    {"ms-per-test", 'm', "test length in ms", MYARGS_INTEGER, {.integer = 1000}},
    {"delay",  'D', "delay starting testing after features_reply is received (in ms)", MYARGS_INTEGER, {.integer = 0}},
    {"dpid-offset", 'o', "switch DPID offset", MYARGS_INTEGER, {.integer = 1}},
    {"pcap-file",   'r', "send traffic from pcap file", MYARGS_STRING, {.string = "/home/cchliu/COST/input/wifi_test/pcap/mu_03284_20140530132156"}},
    {0, 0, 0, 0}
};

/*******************************************************************/
int switch_controller_ready(int n_fakeswitches, struct fakeswitch *fakeswitches, int delay)
{
    struct timeval now, then, diff;
    int i;
    double sum = 0;
    double passed;
    int count;

    //int total_wait = delay;
    //time_t tNow;
    //struct tm *tmNow;
    gettimeofday(&then,NULL);
    while(1)
    {
        gettimeofday(&now, NULL);
        timersub(&now, &then, &diff);
        //if( (1000* diff.tv_sec  + (float)diff.tv_usec/1000)> total_wait)
        //    break;

        #ifdef USE_EPOLL
        for(i = 0; i < MAX_EVENTS; i++) {
            events[i].events = EPOLLIN | EPOLLOUT;
        }

        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);

        //printf("Number of nfds %d\n", nfds);
        for(i = 0; i < nfds; i++) {
            fakeswitch_handle_io(events[i].data.ptr, &(events[i].events));
        }
        #endif
    }
    return 1;
}
/********************************************************************************/
int timeout_connect(int fd, const char* hostname, int port, int mstimeout){
    int ret=0;
    int flags;
    fd_set fds;
    struct timeval tv;
    struct addrinfo *res=NULL;
    struct addrinfo hints;
    char sport[BUFLEN];
    int err;

    hints.ai_flags          = 0;
    hints.ai_family         = AF_INET;
    hints.ai_socktype       = SOCK_STREAM;
    hints.ai_protocol       = IPPROTO_TCP;
    hints.ai_addrlen        = 0;
    hints.ai_addr           = NULL;
    hints.ai_canonname      = NULL;
    hints.ai_next           = NULL;

    snprintf(sport, BUFLEN, "%d", port);
    err = getaddrinfo(hostname, sport, &hints, &res);
    if(err || (res==NULL)){
        if(res)
            freeaddrinfo(res);
        return -1;
    }
    
    // set non blocking
    if((flags = fcntl(fd, F_GETFL)) < 0) {
        fprintf(stderr, "timeout_connect: unable to get socket flags\n");
        freeaddrinfo(res);
        return -1;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "timeout_connect: unable to put the socket in non-blocking mode\n");
        freeaddrinfo(res);
        return -1;
    }
    
    #ifdef USE_EPOLL
    struct epoll_event ev;
    int epollfd = epoll_create(1);
    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1){
        printf("Cannot use epoll to create connection\n");
        return -1; 
    }
    #endif

    if(mstimeout > 0){
        errno = 0;
        if(connect(fd, res->ai_addr, res->ai_addrlen) < 0){
            if((errno != EWOULDBLOCK) && (errno != EINPROGRESS)){
                fprintf(stderr, "timeout_connect: error connecting: %d\n", errno);
                freeaddrinfo(res);
                return -1;
            }
        }
        #ifdef USE_EPOLL
        int nfds = epoll_wait(epollfd, &ev, 1, mstimeout);
        #endif
    }

    freeaddrinfo(res);

    #ifdef USE_EPOLL
    if(ev.events & EPOLLERR){
        return -1;
    } else{
        return 0;
    }
    #endif
}
/********************************************************************************/
int make_tcp_connection_from_port(const char * hostname, unsigned short port, unsigned short sport,
        int mstimeout, int nodelay)
{
    struct sockaddr_in local;
    int s;
    int err;
    int zero = 0;

    s = socket(AF_INET,SOCK_STREAM,0);
    if(s<0){
        perror("make_tcp_connection: socket");
        exit(1);  // bad socket
    }
    if(nodelay && (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero)) < 0))
    {
        perror("setsockopt");
        fprintf(stderr,"make_tcp_connection::Unable to disable Nagle's algorithm\n");
        exit(1);
    }
    local.sin_family=PF_INET;
    local.sin_addr.s_addr=INADDR_ANY;
    local.sin_port=htons(sport);

    err=bind(s,(struct sockaddr *)&local, sizeof(local));
    if(err)
    {
        perror("make_tcp_connection_from_port::bind");
        return -4;
    }

    err = timeout_connect(s,hostname,port, mstimeout);

    if(err)
    {
        perror("make_tcp_connection: connect");
        close(s);
        return err; // bad connect
    }
    return s;
}

/********************************************************************************/
int make_tcp_connection(const char * hostname, unsigned short port, int mstimeout, int nodelay)
{
    return make_tcp_connection_from_port(hostname,port, INADDR_ANY, mstimeout, nodelay);
}

/********************************************************************************/
#define PROG_TITLE "USAGE: cbench [option] # by Rob Sherwood 2010"
int main(int argc, char* argv[])
{
    struct fakeswitch *fakeswitches;
    char *  controller_hostname = myargs_get_default_string(my_options,"controller");
    int     controller_port      = myargs_get_default_integer(my_options, "port");
    int     n_fakeswitches = myargs_get_default_integer(my_options, "switches");
    int     debug = myargs_get_default_flag(my_options, "debug");
    int     total_mac_addresses = myargs_get_default_integer(my_options, "mac-addresses");
    int     mstestlen = myargs_get_default_integer(my_options, "ms-per-test");
    int     dpid_offset = myargs_get_default_integer(my_options, "dpid-offset");
    int     delay = myargs_get_default_integer(my_options, "delay");
    char *  pcap_file = myargs_get_default_string(my_options, "pcap-file");
    int     mode = MODE_LATENCY;

    const struct option* long_opts = myargs_to_long(my_options);
    char* short_opts = myargs_to_short(my_options);
    printf("short arguments: %s\n", short_opts);
    /* parse args here */
    while(1){
        int c;
        int option_index = 0;
        c = getopt_long(argc, argv, short_opts, long_opts, &option_index);
        if (c == -1)
            break;
        switch (c){
            case 'c':
                controller_hostname = strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'p':
                controller_port = atoi(optarg);
                break;
            case 'r':
                pcap_file = strdup(optarg);
                break;
            case 's':
                n_fakeswitches = atoi(optarg);
                break;
            case 'm':
                mstestlen = atoi(optarg);
                break;
            case 'o':
                dpid_offset = atoi(optarg);
                break;
            case 'D':
                delay = atoi(optarg);
                break;
            case 'M':
                total_mac_addresses = atoi(optarg);
                break;
            default:
                myargs_usage(my_options, PROG_TITLE, "help message", NULL, 1);
        }
    }
    fprintf(stderr, "cbench: controller benchmarking tool\n"
                "running in mode %s\n"
                "connection to controller at %s:%d \n"
                "faking %d switches offset %d :: %d ms per test\n"
                "with %d unique source MACs per switch\n"
                "starting the test with %d ms delay after features_replay\n"
                "reading traffic from %s\n",
                mode == MODE_THROUGHPUT?"'throughput'":"'latency'",
                controller_hostname,
                controller_port,
                n_fakeswitches,
                dpid_offset,
                mstestlen,
                total_mac_addresses,
                delay,
                pcap_file);
    /* done parsing args */
    fakeswitches = malloc(n_fakeswitches * sizeof(struct fakeswitch));
    assert(fakeswitches);
    
    #ifdef USE_EPOLL
    fprintf(stderr, "Use epoll\n");
    struct epoll_event ev;
    epollfd = epoll_create(4096);
    if(epollfd == -1){
        fprintf(stderr, "Cannot create epollfd.\n");
        exit(1);
    }
    #endif
    
    int i;
    for(i=0; i< n_fakeswitches; i++){
        int sock;
        sock = make_tcp_connection(controller_hostname, controller_port, 3000, mode!=MODE_THROUGHPUT);
        if(sock < 0){
            fprintf(stderr, "make_nonblock_tcp_connection :: returned %d\n", sock);
            exit(1);
        }
        fprintf(stderr, "Initializing switch %d ...\n", i+1);
        fflush(stderr);
        #ifdef USE_EPOLL
        fakeswitch_init(&fakeswitches[i], dpid_offset+i, sock, BUFLEN, debug, delay, mode, total_mac_addresses, pcap_file);
        #endif

        #ifdef USE_EPOLL
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = sock;
        ev.data.ptr = &fakeswitches[i];
        if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1){
            fprintf(stderr, "Cannot add sock to epoll\n");
            exit(1);
        }
        #endif
        
        switch_controller_ready(i+1, fakeswitches, delay);         
    }
    return 0;
}
     
