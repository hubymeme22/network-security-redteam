from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


class NetworkListenerPacketModifyer:
    """
    Programmable packet modifyer callback
    """
    def __init__(self):
        pass

    def __call__(self, packet: Packet):
        packet.accept()


class NetworkRedirectAttack:
    """
    TLDR; Openredirect attack through network.
    Network -> hard to detect -> silent -> attacker happy

    A simple request interceptor for redirecting specific http traffic
    to a specified http(s) location. The goal of this interceptor is to beat
    SSL by strictly downgrading HTTPS -> HTTP and redirecting HTTP traffic to
    a specific location.
    """
    def __init__(
        self,
        target_ip: str,
        target_server_ip: str,
        location_redirect: str
    ):
        self.target_ip = target_ip
        self.target_server_ip = target_server_ip
        self.location_redirect = location_redirect
        self.netfilter = NetfilterQueue()

    def execute(self):
        try:
            # listener template
            network_listener = NetworkListenerPacketModifyer()

            # bind to queue number 1 from iptables (see scripts/os-proxy-setup.sh)
            self.netfilter.bind(1, network_listener)
            self.netfilter.run()
        except KeyboardInterrupt:
            print("\n[*] Unbinding queue...")
            self.netfilter.unbind()
