# Python UDP Host Discovery
UDP Host Discovery is a Python-based network scanning tool that enables efficient identification of active hosts on a local network. By utilizing UDP probes and ICMP responses, the tool rapidly scans a subnet, providing administrators with valuable insights into reachable hosts.

## Packet sniffing on Windows and linux
Although accessing raw sockets in Windows differs differently from that in Linux, we want the ability to use the same sniffer across many platforms. We'll make a socket object and then figure out what platform we're using to account for this. By using a socket input/output control (IOCTL), Windows requires us to provide a few extra flags in order to enable promiscuous mode on the network interface.
In the first instance (ip_packet_capture), we simply configured the raw socket sniffer, read in a single packet, and terminated the program.
