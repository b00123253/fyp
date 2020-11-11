#!/usr/bin/env python3
# need winpcap / npcap installed for scapy L3 attacks, ust install wireshark


import os
# task 1
from arp_poison import *
# task 2
from icmp_redirect import *
# task 3
from syn_flood import *
# task 4
from tcp_reset import *
# task 5 & 6
from icmp_attacks import *
# task 7
from tcp_session_hijack import *
from tcp_html_session_hijack import *

clear = lambda: os.system('clear')
choice = 0
while(choice != 5):
    clear()
    print("1. Arp Posion")
    print("2. ICMP Redirect")
    print("3. SYN Flood")
    print("4. TCP Reset")
    print("5. ICMP Attacks")
    print("6. Session Hijack")
    print("7. Quit")
    choice = input("Select attack: ")

    if choice == str(1):
        arp_poison.execute()
    elif choice == str(2):
        icmp_redirect.execute()
    elif choice == str(3):
        syn_flood.execute()
    elif choice == str(4):
        print("1. HTTP")
        print("2. HTTPS")
        print("3. Telnet")
        print("4. SSH")
        attack = input("Select attack: ")
        tcp_reset.execute(attack)
    elif choice == str(5):
        print("1. Blind Connection Reset")
        print("2. Source Quench")
        attack = input("Select attack: ")
        if attack == str(1):
            icmp_attacks.execute(1)
        elif attack == str(2):
            icmp_attacks.execute(2)
        else:
            print("Invalid Selection")
            input("Press enter to continue...")
    elif choice == str(6):
        tcp_html_session_hijack.execute()
    elif choice == str(7):
        sys.exit(0)
    else: 
        print("invalid option")
