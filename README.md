# Python UDP Host Discovery
UDP Host Discovery is a Python-based network scanning tool that enables efficient identification of active hosts on a local network. By utilizing UDP probes and ICMP responses, the tool rapidly scans a subnet, providing administrators with valuable insights into reachable hosts.

## Packet sniffing on Windows and linux
Although accessing raw sockets in Windows differs differently from that in Linux, we want the ability to use the same sniffer across many platforms. We'll make a socket object and then figure out what platform we're using to account for this. By using a socket input/output control (IOCTL), Windows requires us to provide a few extra flags in order to enable promiscuous mode on the network interface.
In the first instance `ip_packet_capture.py`, we simply configured the raw socket sniffer, read in a single packet, and terminated the program.

## Decoding the IP Layer
In the previous code, all IP headers as well as any higher-level protocols like TCP, UDP, or ICMP are received by our sniffer.
The data is compressed into binary form, making it very challenging to grasp. So, in order to extract relevant information from the packet, such as the protocol type (TCP, UDP, or ICMP) and the source and destination IP addresses, we need to decode the IP section of the packet. This will act as the starting point for additional protocol parsing.

The actual packet on the network looks like this, and this will help us understand how to decode the incoming packets:
![IPv4_Packet-en svg](https://github.com/MoAli-sec/UDP-Host-Discovery/assets/73645329/1960919c-8e26-4722-a563-18433989088b)

The protocol type, source IP address, and destination IP address will all be extracted when the IP header has been fully decoded (apart from the options field). As a result, we will be working directly with the binary and will need to develop a Python technique for separating the various components of the IP header.

Fortunitly in python we have couple of ways to get external binary data into a data structure. We can use either the ctypes module or the struct module to define the data structure.

- ## The ctypes Module
     The ctypes module is a module that provides a bridge to C-based languages, enabling you to use C-copatible data types and call function in shared libraries.
     The code `ip_header_ctypes.py` defines a new class, that can read a packet and parse the header into its separate fields.
