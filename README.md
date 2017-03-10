# SDN-Defense
SDN-Defense is a framework supporting new network services by piggybacking network functions on the initial packets sent to the controller
  - Leveraging the benefit of initial flow packets
  - Leveraging the programmable data plane and control plane in SDN

### Install P4 and configuration
A very good starting point is following the tutorial [here](https://github.com/p4lang/tutorials/tree/master/SIGCOMM_2015#exercise-1-source-routing)

I am using Ubuntu 16.10 on my machine and it works fine. After finishing the installation of bmv2 and p4c-bmv2, it is good to try out the source_routing example and make sure you could run the example without errors. Now so far so good.

### Create Mininet Topology
Topology: 
```
h1 -- s1 (P4 simple_switch) -- s2 (OVS) -- h2
                 |
                 h3
```
I will first create the left part (ommiting OVS). 

### Install Snort
There is a very good tutorial on installing Snort (2.9.9.x) on Ubuntu 14 and 16. The tutorial link is [here](https://www.snort.org/documents/snort-2-9-9-x-on-ubuntu-14-16)
