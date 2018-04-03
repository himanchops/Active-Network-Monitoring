import socket
import sys
from decode import *

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        ethernet = Ethernet(raw_data)
        if ethernet.proto == 8:
            #IPV4
            ipv4 = IPv4(ethernet.data)
            if ipv4.proto == 1:
                #Icmp
                icmp = ICMP(ipv4.data)
            elif ipv4.proto == 6:
                #Tcp
                tcp = TCP(ipv4.data)
            elif ipv4.proto == 17:
                #Udp
                upd = UDP(ipv4.data)
            elif ipv4.proto == 88:
                #Igmp
                igmp = IGMP(ipv4.data)
        elif ethernet.proto == 1544:
            #Arp
            arp = ARP(ethernet.data)
        elif ethernet.proto == 13576:
            #Rarp
            rarp = RARP(ethernet.data)
        elif ethernet.proto == 56710:
            #Ipv6
            ipv6 = IPv6(ethernet.data)



if __name__ == '__main__':
    main()
