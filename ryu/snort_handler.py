import os
import sys
import pwd, grp
import socket
import logging

from ryu.base import app_manager
from ryu.lib import hub

import alertpkt
import alert_parser
import snort_event

path = os.path.dirname(alert_parser.__file__)
print path


SOCKFILE = "/tmp/snort_alert"
BUFSIZE = 100000

"""
class EventAlert(event.EventBase):
    def __init__(self, alertmsg, timestamp, event, flow):
        super(EventAlert, self).__init__()
        self.alertmsg = alertmsg
        self.tv_sec = timestamp.tv_sec
        self.tv_usec = timestamp.tv_usec
        self.gid, self.sid, self.rev, self.classification, self.priority, self.cid = event
        self.proto, self.srcIp, self.srcPort, self.dstIp, self.dstPort = flow
"""

class SnortHandler(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SnortHandler, self).__init__(*args, **kwargs)
        self.name = 'snort_event'
        self.unsock = None

    def start(self):
        super(SnortHandler, self).start()
        return hub.spawn(self.start_unsock_server) 

    def start_unsock_server(self):
        '''Open a server on Unix Domain Socket'''
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.unsock.bind(SOCKFILE)
        #uid = pwd.getpwnam("snort").pw_uid
        #gid = grp.getgrnam("snort").gr_gid
        #os.chown(SOCKFILE, uid, gid)
        self.logger.info("Unix Domain Socket listening...")
        self.recv_loop()

    def recv_loop(self):
        '''Receive Snort alert on Unix Domain Socket'''
        #count = 0
        while True:
            data = self.unsock.recv(BUFSIZE)
            #count += 1
            #self.logger.info('Received {0} alert...'.format(count))
            #print count
            #sys.stdout.flush()
            
            try:
                if len(data):
                    msg = alertpkt.AlertPkt.parser(data)
                    alertmsg = alert_parser.parse_altmsg(msg.alertmsg)
                    timestamp = msg.pkth.ts
                    event = alert_parser.parse_event(msg.event)
                    record = alert_parser.parse_pckt(msg.pkt)
                    self.send_event_to_observers(snort_event.EventAlert(alertmsg, timestamp, event, record))
            except Exception as err:
                self.logger.error(str(err))
