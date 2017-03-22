# SDN-Defense
## Introduction
SDN-Defense is a framework supporting new network services by piggybacking network functions on the initial packets sent to the controller
  - Leveraging the benefit of initial flow packets
  - Leveraging the programmable data plane and control plane in SDN

The original proposal of SDN-Defense [paper](http://conferences.sigcomm.org/sosr/2017/program.html) piggybacks on reactive routing. In reactive routing, the first packet of each new flow is sent to the controller for routing information. Then the controller responds by installing a forwarding rule for this flow, so that subsequent packets of the same flow will match the flow rule and get forwarded in the dataplane. SDN-Defense proposes to delay installation of the forwarding rule until the first **K** packets of a flow are sent to the controller and inspected at the controller site. The value of **K** is a design parameter tunable by the controller.  

However, reactive routing is not widely deployed in networks, because:
- SDN controller becomes the bottleneck of the network under large traffic rate.
- Additional end-to-end latency is introduced as packets are going through the switch-controller-switch loop. 

As an improved solution, we propose to utilize a combination of [p4-enabled switches](http://p4.org/) and OVS (Open vSwitch) to instantiate the SDN-Defense framework:
- Leverage the capabilities of P4-enabled switches to identify initial flow packets and send a copy of them to the controller, while forwarding packets on as normal to minimize end-to-end delay
- Leverage the openflow interface between OVS and SDN controller for attack mitigation

This demo is a feasibility study of the above proposal.
## Demo Overview

```
               +--------------------------+
               |        controller        |
               |    snort   ==>   Ryu     |
               +----eth0----------eth1----+
                     |             |
    +-------+   +----------+   +-------+   +-------+
    | HostA |---| P4Switch |---|  OVS  |---| HostB |
    +-------+   +----------+   +-------+   +-------+
```
The above depicts the architecture of the demo. HostA servers as an traffic generator and sends packets to HostB. When packets are processed in the P4Switch, they are forwarded on to the next hop as usual, and the first **K** packets of each flow are identified and a copy of them are sent to the controller (interface eth0). An instance of Snort sniffs packets on interface eth0 and sending alerts to the controler application via Unix Domain Socket. The controller application is developed in Ryu. When it receives an alert from Snort, it extracts the 5-tuple information about the malicious flow and installs a rule into OVS to drop this flow.

## Installing required software
### Install P4
A very good starting point is following this [tutorial](https://github.com/p4lang/tutorials/tree/master/SIGCOMM_2015#exercise-1-source-routing). I am runnning Ubuntu 16.10 on my machine and it works fine. After finishing the installation of bmv2 and p4c-bmv2, it is good to try out the source_routing example and make sure you could run the example without errors. Now so far so good.

### Install Ryu 
It is easy to install Ryu SDN framework:
```
sudo pip install ryu
```
### Install Snort
Snort is an open-source signature-based detection engine. There is a very good tutorial on installing Snort (2.9.9.x) on Ubuntu 14 and 16. The tutorial link is [here](https://www.snort.org/documents/snort-2-9-9-x-on-ubuntu-14-16).

I am using:
- daq-2.0.6
- snort version 2.9.9.0

  ```
     ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.9.0 GRE (Build 56) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.7.4
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.8
  ```
- barnyard2 version 2.1.14

  ```
      ______   -*> Barnyard2 <*-
     / ,,_  \  Version 2.1.14 (Build 337)
     |o"  )~|  By Ian Firns (SecurixLive): http://www.securixlive.com/
     + '''' +  (C) Copyright 2008-2013 Ian Firns <firnsy@securixlive.com>

  ```
- pulledpork version 0.7.3

  ```
   PulledPork v0.7.3 - Making signature updates great again!
  ```
The ruleset I am using (you need to remove the tarballs stored at /tmp in order to re-generate the snort.rules file):
```
Rule Stats...
	New:-------31991
	Deleted:---0
	Enabled Rules:----10888
	Dropped Rules:----0
	Disabled Rules:---21103
	Total Rules:------31991
IP Blacklist Stats...
	Total IPs:-----26853
```
## Development
We note down major steps developing the demo.
#### 1. Create topology
Topology: 
```
             +--------------------------+
             |        controller        |
             |    snort   ==>   Ryu     |
             +----eth0----------eth1----+
                   |             |
    +-------+   +-------+   +-------+   +-------+
    |  h1   |---|  s1   |---|  s2   |---|  h2   |
    +-------+   +-------+   +-------+   +-------+
```
**[Option 1]**
Reference to the [example](https://github.com/p4lang/tutorials/tree/master/SIGCOMM_2015/source_routing), we create the above topology in mininet, where s1 is a P4 switch (simple_switch target) and s2 is an OVS. Source code is located under /demo.

**[Option 2]**
Directly create virtual interfaces and link these interfaces with software switches. Source code is located under /demo:
- [reference code](https://github.com/p4lang/tutorials/blob/master/SIGCOMM_2015/flowlet_switching/run_demo.sh) for loading and starting p4 switch
- [reference code](http://groups.geni.net/geni/wiki/GENIExperimenter/Tutorials/OpenFlowOVS/DesignSetup) for starting OVS

Distribution of virtual interfaces is shown below:
```
                            +----veth7-------------------------eth1----+
                                   |                            |
				 veth6                        OF Path
    +-------+                 +----------+                  +-------+                 +-------+
    | HostA |--veth0---veth1--| P4Switch |--veth2----veth3--|  OVS  |--veth4---veth5--| HostB |
    +-------+                 +----------+                  +-------+                 +-------+
    							      veth8
							        |
							      veth9 (Debug intf)
```
#### 2. Write P4 program 
The p4 program is located under /p4src.

The template for headers.p4 can be found [here](https://github.com/p4lang/switch/blob/master/p4src/includes/headers.p4). In this demo, we define headers of ethernet, vlan_tag, ipv4, tcp and udp in headers.p4. The template for parser.p4 can be found [here](https://github.com/p4lang/switch/blob/master/p4src/includes/parser.p4). In this demo, the parser is defined as following:
<img src="https://github.com/cchliu/SDN-Defense/blob/master/parser.png" width="280">

Forward.p4 is an test program that simply forwards all packets on. We test the connectivity of the above topology by loading forward.p4 program into s1 (P4-enabled simple switch) and proactively configuring s2 to forward all packets to h2. From h1 tcpreplay a probe pacekt, and check if h2 receives it. So far so good. 

Mirror.p4 is based on the example code from [here](https://github.com/p4lang/tutorials/blob/master/SIGCOMM_2016/heavy_hitter/solution.tar.gz). In this program, it calculates the 5-tuple hash for each incoming TCP packet and updates the counter based on the hash index. (Note here, if the packet is a TCP SYN or SYN-ACK packet, it clears the corresponding counter first before accumulating packet count). Then it compares the current counter value with parameter K, if less, a copy of the packet is obtained and sent to the mirroring port (port 3 in this case). Meanwhile, incoming packets are forwarded to output port (port 2) as normal.

#### 3. Snort output format
Run Snort
```
sudo snort -i veth0 -c /etc/snort/snort.conf -u snort -g snort -A unsock -N -l /tmp
```
We use the following flags:
```
 -u snort                      Run Snort as the following user after startup. 
 -g snort                      Run Snort as the following group after startup.
 -N                            Turn off packet logging. The program still generates alerts normally.
 -l /tmp                       Set the output logging directory to /tmp.
 -c /etc/snort/snort.conf      The path to snort.conf
 -A unsock                     Alert using unsock mode. 
```
Unsock mode sends the alert information out over a UNIX socket to another process that attaches to that socket. It turned out that the alert information sent over unsock is not in [unified2](https://www.snort.org/faq/readme-unified2) format. (BTW, a good example on parsing unified2 format can be found here: [unified2](https://github.com/jasonish/py-idstools/blob/master/idstools/unified2.py) and [u2spewfoo](https://github.com/jasonish/py-idstools/blob/master/idstools/scripts/u2spewfoo.py)). Instead, Snort will be sending you **Alertpkt structures** which contain alert message, event id, original datagram, libpcap pkthdr, and offsets to datalink, netlayer, and transport layer headers.

Alertpkt structure is defined in snort *src/output-plugins/spo_alert_unixsock.h* file. File alertpkt.py parses the received datagram from snort into an instance of the Alertpkt structure. File alertpkt.py is written with reference to [reference code](https://github.com/osrg/ryu/blob/master/ryu/lib/alert.py). File parser.py continues parsing the structure to extract from each alertpkt:
- ipv4 protocol
- src ip
- src port
- dst ip
- dst port
- pacekt timestamp
- alert signature ID
- alert msg
- alert classification
- alert priority

### 4. Snort Ryu integration 
Snort will generate less alerts in mode A compared to mode B:
- mode A: tcpreplay pcap file to an virtual interface (mtu = 65535) and Snort is sniffing packets on this interface.
  - Make sure snort is ready commencing packets before we tcpreplay the packets
- mode B: Snort read packets from a pcap file.

The reason is because, packets are being dropped in mode A (incoming packets rate is larger than the packet processing rate of Snort), while in mode B, no packets are dropped; Snort can process packets one at a time.
