from scapy.all import sniff
from networklib.dns import intercept_dns_query

TARGET_IP = "192.168.100.57"

def main():
    print("[*] Starting DNS passive sniffing...")
    sniff(filter=f"src host {TARGET_IP} and udp",prn=intercept_dns_query, store=0)

if __name__ == "__main__":
    main()