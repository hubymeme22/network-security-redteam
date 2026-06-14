#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: os-proxy-setup.sh <TARGET_IP>"
    exit 1
fi

TARGET_IP="$1"

echo "[*] Setting up routing and firewall rules for target: $TARGET_IP"

# ip forwarding
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

# clear existing forward rules
sudo iptables -F FORWARD

sudo iptables -A FORWARD -p tcp --sport 80 -d "$TARGET_IP" -j NFQUEUE --queue-num 1
sudo iptables -A FORWARD -p tcp --dport 80 -s "$TARGET_IP" -j NFQUEUE --queue-num 1

# avoid congestion: forward packets that are already modified by our python code
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# no, no, dont allow 443 packets >:D
sudo iptables -A FORWARD -s "$TARGET_IP" -p tcp --dport 443 -j DROP
sudo iptables -A FORWARD -d "$TARGET_IP" -p tcp --sport 443 -j DROP

echo "[+] Firewall rules successfully applied. You can now launch your Python script."