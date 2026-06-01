from scapy.layers.inet import IP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet


def intercept_dns_query(packet: Packet):
    if packet.haslayer(DNS):
        dns_layer: DNS = packet.getlayer(DNS)
        ip_layer: IP = packet.getlayer(IP)

        # reference for query packet: https://www.catchpoint.com/blog/how-dns-works
        # checks he dns qr flag if set to 0 (means that it is a query)
        if dns_layer.qr == 0:
            dns_query: bytes = packet[DNSQR].qname
            query_name = dns_query.decode('utf-8')
            print(f"[{ip_layer.src}] DNS Query for: {query_name}")
