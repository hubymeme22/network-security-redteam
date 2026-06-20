#!/bin/bash

echo "[*] Cleaning up proxy environment and restoring network defaults..."

sudo iptables -F FORWARD
sudo iptables -P FORWARD ACCEPT
sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null

echo "[+] Firewall restored. IP forwarding disabled. Network is back to normal!"
