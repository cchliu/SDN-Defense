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
The template for parser.p4 can be found [here](https://github.com/p4lang/switch/blob/master/p4src/includes/parser.p4). In our case, the parsing tree is as following:
```
```



### Install Snort
There is a very good tutorial on installing Snort (2.9.9.x) on Ubuntu 14 and 16. The tutorial link is [here](https://www.snort.org/documents/snort-2-9-9-x-on-ubuntu-14-16)
