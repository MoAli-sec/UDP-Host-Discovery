from ctypes import *
import socket
import struct


class IP(Structure):
    _fields_ = [
        ("ihl",           c_ubyte,    4),    # 4 bit unsigned char     # IP header length (4 bits)
        ("version",       c_ubyte,    4),    # 4 bit unsigned char     # IP version (4 bits)
        ("tos",           c_ubyte,    8),    # 1 byte char             # Type of Service (8 bits)
        ("len",           c_ushort,  16),    # 2 byte unsigned short   # Total length of the packet (16 bits)
        ("id",            c_ushort,  16),    # 2 byte unsigned short   # Identification field (16 bits)
        ("offset",        c_ushort,  16),    # 2 byte unsigned short   # Fragmentation offset (13 bits) + Flags (3 bits)
        ("ttl",           c_ubyte,    8),    # 1 byte char             # Time to Live (8 bits)
        ("protocol_num",  c_ubyte,    8),    # 1 byte char             # Protocol number (8 bits)
        ("sum",           c_ushort,  16),    # 2 byte unsigned short   # Header checksum (16 bits)
        ("src",           c_uint32,  32),    # 4 byte unsigned int     # Source IP address (32 bits)
        ("dst",           c_uint32,  32)     # 4 byte unsigned int     # Destination IP address (32 bits)
    ]

    def __new__(cls, socket_buffer=None):
        """
        Creates a new instance of the IP class by creating a structure from the socket buffer.

        :param socket_buffer: Buffer containing the IP header.
        :return: IP object.
        """
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        """
        Initializes the IP object by setting the human-readable source and destination IP addresses.

        :param socket_buffer: Buffer containing the IP header.
        """
        # Human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))


# Example usage:

# Create a socket buffer with the IP header
# ip_header_buffer = b'\x45\x00\x00\x28\x54\x12\x00\x00\x80\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02'

# Create an instance of the IP class by parsing the socket buffer
# ip_header = IP(ip_header_buffer)

# Print the source and destination IP addresses
# print(f"Source IP: {ip_header.src_address}")
# print(f"Destination IP: {ip_header.dst_address}")
