from networklib.arpspoof import getmacbyip

import sys

def ip_range_parser(ip_range: str) -> list[str]:
    """
    accepts ip range, example: 192.168.1.1-20, this should produce
    a list of ip from 192.168.1.1 - 192.168.1.20
    """
    try:
        parsable_ip_range = ip_range.split(".")
        ip_base = ".".join(parsable_ip_range[:3])

        range_base = parsable_ip_range[3].split("-")
        starting, ending = int(range_base[0]), int(range_base[1])
        return [ip_base + "." + str(i) for i in range(starting, ending + 1)]

    except Exception as e:
        print(e)
        print("[!] Parser Failed, the format should be like x.x.x.x-n (ex. 192.168.1.1-20)")
        exit()

def scan_network(ip_range: str):
    ip_range_list = ip_range_parser(ip_range)
    for ip_addr in ip_range_list:
        mac_addr = getmacbyip(ip_addr)
        print(f"[*] Testing address '{ip_addr}'...", end=" ")
        if mac_addr is not None:
            print(f"active address! with mac-address of '{mac_addr}'")
        else:
            print("Not Reachable")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: network_arp_scan.py <ip_range>")
        exit()
    scan_network(sys.argv[1])
