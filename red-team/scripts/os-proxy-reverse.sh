#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: os-proxy-reverse.sh <TARGET_IP>"
    exit 1
fi

TARGET_IP="$1"

# simple script to forward traffic to the client
sudo sysctl -w net.ipv4.ip_forward=0

# drop 443 packets to strictly proceed on port 80 packets
sudo iptables -D FORWARD -s "$TARGET_IP" -p tcp --dport 443 -j DROP
sudo iptables -D FORWARD -d "$TARGET_IP" -p tcp --sport 443 -j DROP
sudo iptables -D FORWARD -p tcp --sport 80 -d "$TARGET_IP" -j NFQUEUE --queue-num 1
