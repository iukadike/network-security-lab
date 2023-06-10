#!/usr/bin/env python3
import sys
from scapy.all import *

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: ./sniff_spoof.py INTERFACE")
    
    iface_ = sys.argv[1]
    print(f'listening for packets on {iface_}')
    sniff(iface = iface_, filter = 'icmp', prn = sniff_)
    
def sniff_(pkt):
    if pkt[ICMP].type == 8:
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
        icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
        data = pkt[Raw].load
        send(ip/icmp/data, verbose=0)
    elif pkt[ICMP].type == 0:
        print(pkt.sprintf("%IP.src% -> %IP.dst%"))
        
        
if __name__ == '__main__':
    main()
