#!/usr/bin/env python3
import sys
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        sys.exit('Usage: ./sniffer.py <INTERFACE> <SUBNET>')
    # main
    iface_ = sys.argv[1]
    net_ = sys.argv[2]
    print(f'listening on {iface_}')
    sniff(iface=iface_, filter=f'net {net_}', prn=print_pkt)
    
if __name__ == '__main__':
    main()
