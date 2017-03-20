# SDN-Defense
SDN-Defense is a framework supporting new network services by piggybacking network functions on the initial packets sent to the controller
  - Leveraging the benefit of initial flow packets
  - Leveraging the programmable data plane and control plane in SDN

### Install P4 and configuration
A very good starting point is following the tutorial [here](https://github.com/p4lang/tutorials/tree/master/SIGCOMM_2015#exercise-1-source-routing)

I am using Ubuntu 16.10 on my machine and it works fine. After finishing the installation of bmv2 and p4c-bmv2, it is good to try out the source_routing example and make sure you could run the example without errors. Now so far so good.

### Install Ryu Controller
It is easy to install Ryu controller:
```
sudo pip install ryu
```

### Create Mininet Topology
Topology: 
```
h1 -- s1 (P4 simple_switch) -- s2 (OVS) -- h2
                 |
                 h3
```
### Write P4 Program 
The p4 program is located under /p4src.

The template for headers.p4 can be found [here](https://github.com/p4lang/switch/blob/master/p4src/includes/headers.p4). In our case, we define headers of ethernet, vlan_tag, ipv4, tcp and udp in headers.p4. 

The template for parser.p4 can be found [here](https://github.com/p4lang/switch/blob/master/p4src/includes/parser.p4). In our case, the parser is defined as following: 
<img src="https://github.com/cchliu/SDN-Defense/blob/master/parser.png" width="300">

Forward.p4 is an test program that simply forwards all packets on. We test the connectivity of the above topology by loading forward.p4 program into s1 (P4-enabled simple switch) and proactively configuring s2 to forward all packets to h2. From h1 tcpreplay a probe pacekt, and check if h2 receives it. So far so good. 

Mirror.p4 is based on the example code from [here](https://github.com/p4lang/tutorials/blob/master/SIGCOMM_2016/heavy_hitter/solution.tar.gz). In this program, it calculates the 5-tuple hash for each incoming TCP packet and updates the counter based on the hash index. (Note here, if the packet is a TCP SYN or SYN-ACK packet, it clears the corresponding counter first before accumulating packet count). Then it compares the current counter value with parameter K, if less, a copy of the packet is obtained and sent to the mirroring port (port 3 in this case). Meanwhile, incoming packets are forwarded to output port (port 2) as normal.


### Install Snort
There is a very good tutorial on installing Snort (2.9.9.x) on Ubuntu 14 and 16. The tutorial link is [here](https://www.snort.org/documents/snort-2-9-9-x-on-ubuntu-14-16).

I am using:
- daq-2.0.6

  Available DAQ Modules:
  ```
  Build AFPacket DAQ module.. : yes
  Build Dump DAQ module...... : yes
  Build IPFW DAQ module...... : yes
  Build IPQ DAQ module....... : no
  Build NFQ DAQ module....... : no
  Build PCAP DAQ module...... : yes
  Build netmap DAQ module.... : no
  ```
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
The ruleset I am using is:
```
Rule Totals
    New:-------31173
    Deleted:---0
    Enabled:---10065
    Dropped:---0
    Disabled:--21108
    Total:-----31173

IP Blacklist Stats
    Total IPs:-----26853
```

### Snort output format
Run Snort
```
sudo snort -i eno1 -c /etc/snort/snort.conf -u snort -g snort -A unsock -q -N -l /tmp
```
We use the following flags:
```
 -u snort                      Run Snort as the following user after startup. 
 -g snort                      Run Snort as the following group after startup.
 -q                            Quiet mode. Don’t show banner and status report.
 -N                            Turn off packet logging. The program still generates alerts normally.
 -l /tmp                       Set the output logging directory to /tmp.
 -c /etc/snort/snort.conf      The path to snort.conf
 -A unsock                     Alert using unsock mode. 
```
Unsock mode sends the alert information out over a UNIX socket to another process that attaches to that socket. It turned out that the alert information sent over unsock is not in [unified2](https://www.snort.org/faq/readme-unified2) format. Instead, Snort will be sending you **Alertpkt structures** which contain alert message, event id, original datagram, libpcap pkthdr, and offsets to datalink, netlayer, and transport layer headers.

A good example on parsing unified2 format can be found here: [unified2](https://github.com/jasonish/py-idstools/blob/master/idstools/unified2.py) and [u2spewfoo](https://github.com/jasonish/py-idstools/blob/master/idstools/scripts/u2spewfoo.py).

Alertpkt structure is defined in snort src/output-plugins/spo_alert_unixsock.h file.




