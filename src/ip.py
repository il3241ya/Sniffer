from ctypes import *
import socket
import struct
import ipaddress


class IP:
    """
    Represents an IP packet header.

    Attributes:
        ver (int): IP version.
        ihl (int): IP header length.
        tos (int): Type of Service.
        len (int): Total length of the IP packet.
        id (int): Identification.
        offset (int): Fragment offset.
        ttl (int): Time-to-Live.
        protocol_num (int): Protocol number.
        sum (int): Header checksum.
        src (bytes): Source IP address in raw format.
        dst (bytes): Destination IP address in raw format.
        src_address (ipaddress.IPv4Address): Source IP address.
        dst_address (ipaddress.IPv4Address): Destination IP address.
        protocol (str): Protocol name (ICMP, TCP, UDP, etc.).
        protocol_map (dict): Mapping of protocol numbers to names.
    """

    def __init__(self, buff=None):
        """
        Initializes the IP object.

        Args:
            buff (bytes): Raw buffer containing the IP packet.
        """
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

        self.src_address = ipaddress.ip_address(self.src) 
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f'{e} No protocol for {self.protocol_num}')
            self.protocol = str(self.protocol_num)
