#!/usr/bin/env python3
import sys
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

def main():
    # Ensure correct usage
    if len(sys.argv) != 4:
        sys.exit('Usage: ./sniffer.py <INTERFACE> <IP-ADDRESS> <PORT>')
    # main
    iface_ = sys.argv[1]
    s_addr = sys.argv[2]
    d_port = sys.argv[3]
    print(f'listening on {iface_}')
    sniff(iface=iface_, filter=f'(src host {s_addr}) && (tcp dst port {d_port})', prn=print_pkt)
    
if __name__ == '__main__':
    main()
