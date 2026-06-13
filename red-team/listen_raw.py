from scapy.all import sniff
from networklib.network_callbacks import intercept_raw_packets

import sys

def main():
    if len(sys.argv) > 1:
        print("[*] Starting Raw unencrypted traffic active sniffing...")
        sniff(filter=f"src host {sys.argv[1]} and tcp",prn=intercept_raw_packets, store=0)
    else:
        print("Usage: listen_http.py <target_ip_address>")

if __name__ == "__main__":
    main()
