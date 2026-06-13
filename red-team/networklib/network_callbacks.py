from io import FileIO
from networklib.utils.parser_utils import parse_http_request
from networklib.utils.parser_utils import unencrypted_packet_capture
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from typing import Callable

import json

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


def intercept_raw_packets(packet: Packet, log_fp: FileIO = None, action: Callable[[dict, Packet], None] = None):
    """
    flexible callback for catching raw unencrypted traffic in the
    network and a designed callback for programmability (is this even a word?)
    """
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_layer: Packet = packet[Raw]
        raw_packet: str = raw_layer.load
        if raw_packet is not None:
            packet_parsed_contents = unencrypted_packet_capture(packet)
            if packet_parsed_contents is None:
                return

            if action is not None:
                action(packet_parsed_contents, packet)

            # terminal log
            print("Packet Detected:")
            print(json.dumps(packet_parsed_contents, indent=2))
            print()

            # save logs to disk if log_fileio is specified
            # global_logs.append(packet_parsed_contents)
            if log_fp is not None:
                log_fp.write(json.dumps(packet_parsed_contents) + "\n")

