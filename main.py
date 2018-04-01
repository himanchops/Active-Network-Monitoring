import socket
import sys
from decode import Ethernet

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        ethernet = Ethernet(raw_data)
        if ethernet.proto == 8:
            #IPV4
            pass
        elif ethernet.proto == 1544:
            #ARP
            pass
        elif ethernet.proto == 13576:
            #RARP
            pass
        elif ethernet.proto == 56710:
            #IPV6
            pass



if __name__ == '__main__':
    main()
