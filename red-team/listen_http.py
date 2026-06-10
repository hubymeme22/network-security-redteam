from scapy.all import sniff
from networklib.network_callbacks import intercept_http_requests

import sys

def main():
    if len(sys.argv) > 1:
        print("[*] Starting HTTP passive sniffing...")
        sniff(filter=f"src host {sys.argv[1]} and tcp",prn=intercept_http_requests, store=0)
    else:
        print("Usage: listen_http.py <target_ip_address>")

if __name__ == "__main__":
    main()