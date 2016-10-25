from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.vlan import vlan
from pox.lib.packet.llc import llc
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.arp import arp
from pox.lib.packet.packet_base import packet_base

OFP_VLAN_NONE = 0xffff

log = core.getLogger()

def my_parser(data, in_port):
    match = of.ofp_match()
    # find 5-tuples: proto, src_ip, src_port, dst_ip, dst_port
    if in_port is not None:
        match.in_port = in_port
    # parse ethernet
    packet = ethernet(data)
    match.dl_type = packet.type
    #print packet.src, packet.dst
    p = packet.next

    # parse VLAN
    if packet.type == ethernet.VLAN_TYPE:
        match.dl_type = p.eth_type
        match.dl_vlan = p.id
        match.dl_vlan_pcp = p.pcp
        p = p.next
    else:
        match.dl_vlan = OFP_VLAN_NONE
        match.dl_vlan_pcp = 0

    # parse ipv4
    if match.dl_type != ethernet.IP_TYPE:
        # non ipv4 packets
        log.debug("Packet_in: non-ipv4 packets, dropped")
        return None

    if match.dl_type == ethernet.IP_TYPE:
        match.nw_src = p.srcip
        match.nw_dst = p.dstip
        match.nw_proto = p.protocol
        print hex(match.nw_proto)
        # TODO: ip fragmentation
        # This seems a bit strange, but see page 9 of the spec
        if ((p.flags & p.MF_FLAG) or (p.frag != 0)):
            match.tp_src = 0
            match.tp_dst = 0
        p = p.next

        if not isinstance(p, packet_base):
            log.debug("Packet_in: can not parse transport layer")
            return None
        # parse TCP
        if match.nw_proto == ipv4.TCP_PROTOCOL:
            match.tp_src = p.srcport
            match.tp_dst = p.dstport
        # parse UDP
        elif match.nw_proto == ipv4.UDP_PROTOCOL:
            match.tp_src = p.srcport
            match.tp_dst = p.dstport
        else:
            # non TCP/UDP packets
            log.debug("Packet_in: non tcp/udp packets, dropped")
            return None

    return match

