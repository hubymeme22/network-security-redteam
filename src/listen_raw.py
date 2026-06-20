from scapy.all import sniff
from scapy.packet import Packet
from networklib.network_callbacks import intercept_raw_packets

import argparse
import os

class PacketLogger:
    def __init__(self, log_path=None):
        self.log_path = log_path
        self.file_pointer = None

        if self.log_path:
            self.file_pointer = open(self.log_path, "w", buffering=1)

    def __call__(self, packet: Packet):
        """ makes the class instance act exactly like a function callback for scapy."""
        if self.file_pointer:
            return intercept_raw_packets(packet, self.file_pointer)
        else:
            return intercept_raw_packets(packet)

    def close(self):
        if self.file_pointer:
            self.file_pointer.close()

def main():
    #######################
    #  Parser definition  #
    #######################
    parser = argparse.ArgumentParser(
        description="Active raw network sniffer targeting unencrypted TCP traffic."
    )

    parser.add_argument(
        "target_ip", 
        help="The target IP address to sniff traffic from (e.g., 192.168.1.50)"
    )

    parser.add_argument(
        "-f", "--filter",
        default=None,
        help="Overwrite the default BPF filter with a custom string (e.g., 'tcp port 80')"
    )

    parser.add_argument(
        "-l", "--log",
        default=None,
        help="Specifies the filepath where the structured jsonl logs are to be stored (note: the output format is jsonl and not json)"
    )

    args = parser.parse_args()

    ################################
    #  Main logic for the process  #
    ################################
    if os.getuid() != 0:
        print("[-] This needs to run as root")
        exit(1)

    if args.filter:
        bpf_filter = args.filter
        print(f"[*] Starting custom active sniffing with filter: '{bpf_filter}'")
    else:
        bpf_filter = f"src host {args.target_ip} and tcp"
        print(f"[*] Starting Raw unencrypted traffic active sniffing on {args.target_ip}...")

    packetlogger = PacketLogger(log_path=args.log)
    sniff(filter=bpf_filter, prn=packetlogger, store=0)

if __name__ == "__main__":
    main()
