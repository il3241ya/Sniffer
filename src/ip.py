from ctypes import *
import socket
import struct
import ipaddress


class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_address = ipaddress.ip_address(self.src) #socket.inet_ntoa(struct.pack('<L',self.src))
        self.dst_address = ipaddress.ip_address(self.dst)#socket.inet_ntoa(struct.pack('<L',self.dst))

        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f'{e} No protocol for {self.protocol_num}')
            self.protocol = str(self.protocol_num)


"""
mypacket = IP(buff)
print(f'{mypacket.src-address} -> {mypacket.dst_address})
"""