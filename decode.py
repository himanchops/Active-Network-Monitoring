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


class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src_ip_addr = self.convert_ip_address(src)
        self.target_ip_addr = self.convert_ip_address(target)
        self.data = raw_data[self.header_length:]
        print(self.src_ip_addr, self.target_ip_addr)

    # Returns properly formatted IPV4 address
    def convert_ip_address(self, addr):
        return '.'.join(map(str, addr))


class ICMP:

    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]
        print(self.type)
