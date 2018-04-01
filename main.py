import socket
import sys
from decode import Ethernet

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        internal_data = Ethernet(raw_data)


if __name__ == '__main__':
    main()
