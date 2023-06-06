#!/usr/bin/env python3
import sys
from scapy.all import *
from time import sleep

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        sys.exit('Usage: ./spoofer.py <SOURCE-ADDRESS> <DESTINATION-ADDRESS>')
    
    # main
    s_addr = sys.argv[1]
    d_addr = sys.argv[2]
    
    # Loop to continuosly send the packet
    while True:
        send(IP(src=s_addr, dst=d_addr)/ICMP())
        sleep(5)

    
if __name__ == '__main__':
    main()
