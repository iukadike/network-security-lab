#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'ukadike%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print(f"Interface Name: {ifname}")

# Configure the tun interface
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# Send out a spoof packet using the tun interface
def icmp_spoof(c_pkt):
    # make a copy of the packet
    pkt = IP(bytes(c_pkt))
    
    # delete the checksum to force recalculation
    del(pkt.chksum)
    del(pkt[ICMP].chksum)
    
    # make corrections to the IP header
    pkt[IP].src = c_pkt[IP].dst
    pkt[IP].dst = c_pkt[IP].src
    
    # make corrections to the ICMP header
    pkt[ICMP].type = 0
    
    # send the packet
    os.write(tun, bytes(pkt))
    
    # print packet information to screen
    print(c_pkt.summary())
    print(pkt.summary())


while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
        c_pkt = IP(packet)
        if 'ICMP' in c_pkt and c_pkt[ICMP].type == 0x08:
            icmp_spoof(c_pkt)
        #print(c_pkt.summary())