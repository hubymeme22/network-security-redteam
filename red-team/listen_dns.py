from scapy.all import sniff
from networklib.network_callbacks import intercept_dns_query

import os
import sys

def main():
    if os.getuid() != 0:
        print("[-] This needs to run as root!")
        exit(1)

    if len(sys.argv) > 1:
        print("[*] Starting DNS passive sniffing...")
        sniff(filter=f"src host {sys.argv[1]} and udp",prn=intercept_dns_query, store=0)
    else:
        print("Usage: listen_dns.py <target_ip_address>")

if __name__ == "__main__":
    main()
