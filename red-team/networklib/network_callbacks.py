from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

global_scanned = set()

def intercept_dns_query(packet: Packet, exclude_repeat: bool = True):
    if packet.haslayer(DNS):
        dns_layer: DNS = packet.getlayer(DNS)
        ip_layer: IP = packet.getlayer(IP)

        # reference for query packet: https://www.catchpoint.com/blog/how-dns-works
        # checks he dns qr flag if set to 0 (means that it is a query)
        if dns_layer.qr == 0:
            dns_query: bytes = packet[DNSQR].qname
            query_name = dns_query.decode('utf-8')

            if exclude_repeat:
                if query_name not in global_scanned:
                    global_scanned.add(query_name)
                else:
                    return


            print(f"[{ip_layer.src}] DNS Query for: {query_name}")


def intercept_http_requests(packet: Packet):
    ip_layer: IP = packet.getlayer(IP)

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        http_layer: Packet = packet[TCP]
        raw_layer: Packet = packet[Raw]

        # check the raw content layer
        raw_packet: str = raw_layer.load
        if raw_packet is not None:
            raw_packet_string = raw_packet.decode('utf-8', errors='ignore')
            if "GET" in raw_packet_string or \
                "POST" in raw_packet_string or \
                "HEAD" in raw_packet_string or \
                "DELETE" in raw_packet_string or \
                "PUT" in raw_packet_string:
                print(f"[{ip_layer.src}] Potetial HTTP Packet Detected ==>", http_layer)
                print(raw_packet_string)

