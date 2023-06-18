import ipaddress
import struct


class IP:
    def __init__(self, buff=None):
        # Unpack the binary data according to the IP header structure
        header = struct.unpack('<BBHHHBBH4s4s', buff)

        # Extract individual fields from the header
        self.ver = header[0] >> 4  # Extract version by shifting 4 bits to the right
        self.ihl = header[0] & 0xF  # Extract IHL (Internet Header Length) by applying a bitmask

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


# Usage example
# buff = b'\x45\x00\x00\x2C\x00\x00\x40\x00\x40\x01\xF3\x68\xC0\xA8\x01\x01\xC0\xA8\x01\x02'
# ip_packet = IP(buff)

# print("Version:", ip_packet.ver)
# print("IHL:", ip_packet.ihl)
# print("TOS:", ip_packet.tos)
# print("Length:", ip_packet.len)
# print("ID:", ip_packet.id)
# print("Offset:", ip_packet.offset)
# print("TTL:", ip_packet.ttl)
# print("Protocol Number:", ip_packet.protocol_num)
# print("Checksum:", ip_packet.sum)
# print("Source Address:", ip_packet.src_address)
# print("Destination Address:", ip_packet.dst_address)
