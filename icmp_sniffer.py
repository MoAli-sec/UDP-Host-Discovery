import ipaddress
import os
import socket
import struct
import sys


class IP:
    def __init__(self, buff=None):
        # Unpack the IP header from the buffer
        header = struct.unpack('<BBHHHBBH4s4s', buff)

        # Extract individual fields from the header
        self.ver = header[0] >> 4  # IP version (shifted by 4 bits)
        self.ihl = header[0] & 0xF  # IP header length (lower 4 bits)

        self.tos = header[1]  # Type of Service
        self.len = header[2]  # Total length
        self.id = header[3]  # Identification
        self.offset = header[4]  # Fragment offset
        self.ttl = header[5]  # Time to Live
        self.protocol_num = header[6]  # Protocol number
        self.sum = header[7]  # Checksum
        self.src = header[8]  # Source IP address
        self.dst = header[9]  # Destination IP address

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


class ICMP:
    def __init__(self, buff):
        # Unpack the ICMP header from the buffer
        header = struct.unpack('<BBHHH', buff)

        # Extract individual fields from the header
        self.type = header[0]  # ICMP type
        self.code = header[1]  # ICMP code
        self.sum = header[2]  # Checksum
        self.id = header[3]  # Identification
        self.seq = header[4]  # Sequence number


def sniff(host):
    """
    Sniff network packets and print information about ICMP packets.
    :param host: The host IP address to listen on.
    """
    # Determine the appropriate socket protocol based on the operating system
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    # Create a socket object for sniffing
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

            # Check if the protocol is ICMP
            if ip_header.protocol == "ICMP":
                print("Protocol: %s %s -> %s" % (ip_header.protocol,
                                                 ip_header.src_address, ip_header.dst_address))
                print(f'Version: {ip_header.ver}')
                print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                # Calculate the offset to the start of the ICMP packet within the raw buffer
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                # Create an ICMP structure
                icmp_header = ICMP(buf)
                print('ICMP -> Type: %s Code: %s\n' %
                      (icmp_header.type, icmp_header.code))

    except KeyboardInterrupt:
        # Disable promiscuous mode on Windows
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == "__main__":
    # Get the host IP address from the command line argument, default to '192.168.1.2' if not provided
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.2'
    sniff(host)
