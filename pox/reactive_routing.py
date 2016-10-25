from pox.core import core
import pox.openflow.libopenflow_01 as of
import time

from parser import my_parser
log = core.getLogger()

class CBench (object):
    def __init__ (self, connection):
        self.connection = connection
        connection.addListeners(self)

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in
        
        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        
        # Send message to switch
        self.connection.send(msg)

    def _handle_PacketIn (self, event):
        log.debug("A packet_in is received...")
        data = event.data
        inport = event.port
        packet_in = event.ofp # The actual ofp_packet in message
        
        outport = 2

        match = my_parser(data, inport)
        print match
        if match is None:
            self.resend_packet(packet_in, outport) 
            return
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                        idle_timeout=of.OFP_FLOW_PERMANENT,
                        hard_timeout=of.OFP_FLOW_PERMANENT,
                        action=of.ofp_action_output(port=outport),
                        match=match)
        self.connection.send(msg)
        self.resend_packet(packet_in, outport)

class cbench (object):
    def __init__ (self):
        core.openflow.addListeners(self)
        # set miss length
        core.openflow.miss_send_len = 0xffff
        log.info("Requesting full packet payloads")

    def _handle_ConnectionUp (self, event):
        CBench(event.connection)


def launch ():
    core.registerNew(cbench)

