import array
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800

def parse_altmsg(msg):
    outmsg = ''
    for ch in msg:
        if ch != '\x00':
            outmsg += ch
        else:
            break
    return outmsg

def parse_event(event):
    # Note: integer is sent in this way:
    # switch the highest 2 bytes with the lowest 2 bytes: 0001 => 0100
    # To recover, left shift 16 bits

    # return col: gid, sid, rev, classification, priority, event_count(cid)
    #print type(event.sig_generator)
    return [i>>16 for i in [event.sig_generator, event.sig_id, event.sig_rev, event.classification, \
	event.priority, event.event_id]]

def parse_pckt(pkt):
    pkt = packet.Packet(array.array('B', pkt))
    try:
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
    
        if _ipv4.proto == 6:
            _tcp = pkt.get_protocol(tcp.tcp)
            src_port, dst_port = _tcp.src_port, _tcp.dst_port
        elif _ipv4.proto == 17:
            _udp = pkt.get_protocol(udp.udp)
            src_port, dst_port = _udp.src_port, _udp.dst_port
        return [_ipv4.proto, _ipv4.src, src_port, _ipv4.dst, dst_port]
    except Exception as err:
        print "Error"
        raise err
