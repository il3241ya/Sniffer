from ctypes import *
import socket
import struct


class ICMP(Structure):
    """
    Represents an ICMP packet header.

    Attributes:
        type (int): ICMP message type.
        code (int): ICMP message code.
        sum (int): Checksum value.
        id (int): Identifier value.
        seq (int): Sequence number.
    """
    
    def __init__(self, buff):
        """
        Initializes the ICMP object.

        Args:
            buff (bytes): Raw buffer containing the ICMP packet.
        """
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]