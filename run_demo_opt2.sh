#!/bin/bash

### 
# Setup paired virtual interfaces
###
sudo ./veth_setup.sh

### 
# Start OVS
###
/etc/init.d/openvswitch-switch restart
sudo ovs-vsctl del-br br0
sudo ovs-vsctl add-br br0

sudo ovs-vsctl add-port br0 veth3
sudo ovs-vsctl add-port br0 veth4
sudo ovs-vsctl add-port br0 veth8


#idx=0
#noOfVeths=6
#let "vethpairs=$noOfVeths/2"
#while [ $idx -lt $vethpairs ]
#do
#    intf0="veth$(($idx*2))"
#    intf1="veth$(($idx*2+1))"
#    idx=$((idx + 1))
#	sudo ovs-vsctl add-port br0 $intf1
#done

sudo ovs-vsctl list-ports br0
sudo ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
sudo ovs-vsctl show

### 
# Load and start p4 switch
###
THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/env.sh

P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

set -m
$P4C_BM_SCRIPT p4src/mirror.p4 --json example.json
# This gives libtool the opportunity to "warm-up"
sudo $SWITCH_PATH >/dev/null 2>&1
sudo $SWITCH_PATH example.json \
	-i 1@veth1 -i 2@veth2 -i 3@veth6 \
	--nanolog ipc:///tmp/bm-0-log.ipc &

sleep 2
$CLI_PATH example.json < commands.txt
echo "P4 Switch Ready!!!"
fg

#sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python topo.py \
#    --behavioral-exe $SWITCH_PATH \
#    --json example.json \
#    --cli $CLI_PATH



