import ipaddress
import sys
import socket
import os
import threading
import time
import argparse

from src.ip import IP
from src.icmp import ICMP

MESSAGE = 'CHECKMESSAGE'
HOST  = '' # CHANGE THIS
SUBNET = '' # CHANGE THIS


class Scanner:
    """
    Initializes the Scanner object.

    Args:
        host (str): The host IP address to bind the socket.
    """
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))

        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket,ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    @staticmethod
    def udp_sender():
        """
        Sends UDP messages to all hosts in the specified subnet.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for ip in ipaddress.ip_network(SUBNET).hosts():
                sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))

    def sniff(self):
        """
        Sniffs incoming packets, detects hosts, and prints a summary.
        """
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[0:20])

                if ip_header.protocol == 'ICMP':
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)
                    
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')

        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print('\nUser interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
                for host in sorted(hosts_up):
                    print(f'{host}')
            print('')
            sys.exit()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = HOST
    print('Start sniffing...')
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=Scanner.udp_sender)
    t.start()
    s.sniff()
