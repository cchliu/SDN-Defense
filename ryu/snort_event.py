from ryu.controller import event
from ryu.controller import handler

class EventAlert(event.EventBase):
    def __init__(self, alertmsg, timestamp, event, flow):
        super(EventAlert, self).__init__()
        self.alertmsg = alertmsg
        self.tv_sec = timestamp.tv_sec
        self.tv_usec = timestamp.tv_usec
        self.gid, self.sid, self.rev, self.classification, self.priority, self.cid = event
        self.proto, self.srcIP, self.srcPort, self.dstIP, self.dstPort = flow


handler.register_service('snort_handler')
