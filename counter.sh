#!/bin/bash

idx=0
vethpairs=10
while [ $idx -lt $vethpairs ]
do
    intf="veth$(($idx))"
    var=$( cat /sys/class/net/$intf/statistics/rx_packets)
    echo $intf $var
    idx=$((idx + 1))
done
