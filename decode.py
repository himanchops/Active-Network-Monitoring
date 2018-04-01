import socket
import struct


class Ethernet:

    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac_addr = convert_mac_address(dest)
        self.src_mac_addr = convert_mac_address(src)
        #hex to decimal conversion
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]
        print(self.src_mac_addr, self.dest_mac_addr)



def convert_mac_address(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr
