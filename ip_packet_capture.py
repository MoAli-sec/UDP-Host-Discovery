import socket
import os

# Host to listen on
HOST = '192.168.1.2'


def main():
    # Create raw socket, bin to public interface
    if os.name == 'nt':
        # For Windows, use IPPROTO_IP as the socket protocol
        socket_protocol = socket.IPPROTO_IP
    else:
        # For non-Windows, use IPPROTO_ICMP as the socket protocol
        socket_protocol = socket.IPPROTO_ICMP

    # Create a raw socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    # Bind the socket to the specified host IP and port 0
    sniffer.bind((HOST, 0))
    # Include the IP header in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    if os.name == 'nt':
        # Enable promiscuous mode for Windows
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
    # Read one packet from the network
    print(sniffer.recvfrom(65565))
    
    # if we're on Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        

if __name__ == "__main__":
    main()
