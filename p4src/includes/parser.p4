parser start {
    return parse_ethernet;
}

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_VLAN: parse_vlan_tag;
        ETHERTYPE_IPV4: parse_ipv4;
        default: ingress;
    }
}

header vlan_tag_t vlan_tag;
parser parse_vlan_tag {
    extract(vlan_tag);
    return select(latest.etherType) {
        ETHERTYPE_IPV4: parse_ipv4;
        default: ingress;
    }
}

#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP: parse_tcp;
        IP_PROTOCOLS_UDP: parse_udp;
        default: ingress;
    }
}

header tcp_t tcp;
parser parse_tcp {
    extract(tcp);
    return ingress;
}

header udp_t udp;
parser parse_udp {
    extract(udp);
    return ingress;
}

    
