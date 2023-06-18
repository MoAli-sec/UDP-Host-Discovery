import ipaddress
import os
import socket
import struct
import sys


class IP:
    def __init__(self, buff=None):
        # Unpack the binary data according to the IP header structure
        header = struct.unpack('<BBHHHBBH4s4s', buff)

        # Extract individual fields from the header
        self.ver = header[0] >> 4  # Extract version by shifting 4 bits to the right
        self.ihl = header[0] & 0XF  # Extract IHL (Internet Header Length) by applying a bitmask

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Convert source and destination addresses to human-readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


def sniff(host):
    """
    Sniff network packets and print the detected protocol and hosts.

    :param host: Target host to sniff packets on.
    """
    # Determine the socket protocol based on the operating system
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    # Create a raw socket for sniffing
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode on Windows
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # Read a packet
            raw_buffer = sniffer.recvfrom(65535)[0]
            # Create an IP header from the first 20 bytes
            ip_header = IP(raw_buffer[0:20])
            # Print the detected protocol and hosts
            print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                             ip_header.src_address,
                                             ip_header.dst_address))
    except KeyboardInterrupt:
        # If we're on Windows, turn off promiscuous mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == "__main__":
    # Check command-line arguments for the target host
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.2'  # Default target host

    # Start sniffing
    sniff(host)
