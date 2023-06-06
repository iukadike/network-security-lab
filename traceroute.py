#!/usr/bin/env python3
import sys, os
from scapy.all import *

MAX_TTL = 64

def send_(dst_, ttl_):
    return sr1(IP(dst=dst_, ttl=ttl_)/ICMP(), timeout=1, verbose=0)
    
def result_(hops, dst_):
    print("\n", "*"*3, f"It took {hops} hops to get to {dst_}", "*"*3, "\n")
    
def main():
    # Ensure correct usage
    if len(sys.argv) != 2:
        sys.exit("Usage: ./traceroute.py IP-ADDRESS")
        
    # Set the variables
    dst_ = sys.argv[1]
    ttl_ = 0
    hops = 0
    
    # Loop till you get to the host
    while True:
        ttl_ += 1
        rcv = send_(dst_, ttl_)
        
        if rcv is None:
            hops += 1
            print("--> * * * * *")
            if hops >= MAX_TTL:
                os.system('clear')
                sys.exit(f"Failed to connect to {dst_}. Maybe host is offline?")
        elif rcv[ICMP].type == 3:
            sys.exit("Destination host is unreachable")
        elif rcv[ICMP].type == 11:
            hops += 1
            print(rcv.sprintf("--> %IP.src%"))
        elif rcv[ICMP].type == 0:
            hops += 1
            print(rcv.sprintf("--> %IP.src%"))
            break
    
    result_(hops, dst_)
       
            
if __name__ == '__main__':
    main()
