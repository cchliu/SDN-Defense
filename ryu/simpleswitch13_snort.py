from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

import snort_event

proto_map = {6:'TCP', 17:'UDP'}
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.dp = None
        self.cid = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def set_default_rule(self, ev):
        self.logger.info('Controller connected to switch...')
        # install default forwarding rule
        datapath = ev.msg.datapath
        self.dp = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        out_port = 2
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 0, match, actions)

    def dump_alert(self, ev):
        self.cid += 1
        self.logger.info('Received {0} alert'.format(self.cid))
        self.logger.info('alertmsg: {0}'.format(ev.alertmsg))
        self.logger.info('sid: {0}, classification: {1}, priority: {2}'.format(ev.sid, ev.classification, ev.priority))
        self.logger.info('proto: {0}, {1}:{2} --> {3}:{4}\n'.format(proto_map[ev.proto], ev.srcIP, ev.srcPort, ev.dstIP, ev.dstPort))
        
    @set_ev_cls(snort_event.EventAlert, MAIN_DISPATCHER)
    def alert_handler(self, ev):
        self.dump_alert(ev)
        datapath = self.dp
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if ev.proto == 6:
            # TCP flow, make sure set eth_type
            match = parser.OFPMatch(eth_type = 0x0800, ip_proto=ev.proto, ipv4_src=ev.srcIP, ipv4_dst=ev.dstIP, tcp_src=ev.srcPort, tcp_dst=ev.dstPort)
        elif ev.proto == 17:
            # UDP flow, make sure set eth_type
            match = parser.OFPMatch(eth_type = 0x0800, ip_proto=ev.proto, ipv4_src=ev.srcIP, ipv4_dst=ev.dstIP, udp_src=ev.srcPort, udp_dst=ev.dstPort)
        else:
            return
        # DEBUG: divert malicious flows to out_port 3
        out_port = 3
        actions = [parser.OFPActionOutput(out_port)]
        idle_timeout = 90 #s
        hard_timeout = 300 #s
        self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath = datapath, buffer_id = buffer_id, priority = priority, match = match, instructions = inst, idle_timeout = idle_timeout, hard_timeout = hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath = datapath, priority = priority, match = match, instructions = inst, idle_timeout = idle_timeout, hard_timeout = hard_timeout)
        
        datapath.send_msg(mod)

    
