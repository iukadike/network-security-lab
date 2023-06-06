#!/usr/bin/env python3
import sys
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

def main():
    # Ensure correct usage
    if len(sys.argv) != 2:
        sys.exit('Usage: ./sniffer.py <INTERFACE>')
    # main
    iface_ = sys.argv[1]
    print(f'listening on {iface_}')
    sniff(iface=iface_, filter='icmp', prn=print_pkt)
    
if __name__ == '__main__':
    main()
