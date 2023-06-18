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

- ### The ctypes Module
     The ctypes module is a module that provides a bridge to C-based languages, enabling you to use C-copatible data types and call function in shared libraries.</br>
     The code `ip_header_ctypes.py` defines a class, that can read a packet and parse the header into its separate fields with the use of ctype module.</br>
     Here you simply define how much bits the field requires from referring to the IPv4 header structure above and you give it the suitable kind and length.
     The code has an usage example you can uncomment it and try it.
     
- ### The struct Module
     The struct module provides format characters that we can use to specify the structure of the binary data.</br>
     The code `ip_header_struct.py` define an IP class to hold the header information, But this time we use format characters to represent the parts of the header.</br>
     You can refare to this page to understand how the format characters are set</br> 
     ```
     https://docs.python.org/3/library/struct.html
     ```
     A quick walkthrough on how the formating in this code is done if the </br>
     ```
     buff = b'\x45\x00\x00\x2C\x00\x00\x40\x00\x40\x01\xF3\x68\xC0\xA8\x01\x01\xC0\xA8\x01\x02'</br>
     ```
     
     And the line says `self.ver = header[0] >> 4`
     
     Step 1: Read the first character in the format string: `<` (little-endian byte order).</br>
     
     Step 2: Read the next character in the format string: `B` (unsigned char, 1 byte).</br>
     
     - Take the first byte from the buffer: `\x45`</br>
        
     - Interpret it as an unsigned char: `69` (decimal)</br>
        
     - Assign the value `69` after making a right-shift to it which makes it like:</br>
     
     (We are simply causing the last 4 bits to fall off)</br>
     
            
     ```
       0  1  0  0  0  1  0  1  (69 Decimal)  >>  4
       ---------------------------
       0  0  0  0  0  1  0  0  (4 Decimal)
     ```
     
     Step 3:
     - Finds the line `self.ihl = header[0] & 0xF`</br>
     
     - It has a decimal value of 69 as we demoed above</br>

     - Assign the value `69` after making and AND operation on it with 0xF
     ```
       0  1  0  0  0  1  0  1 (69 in binary)
     & 0  0  0  0  1  1  1  1 (0xF in binary)
      --------------
       0  0  0  0  0  1  0  1 (5 in decimal)

     ```
     Step 4: Read the next character in the format string: `B` (unsigned char, 1 byte).</br>
     
     - From the IPv4 structure we find that the Type of Service takes 1 byte so we assign it without any modification. which we did in `self.tos = header[1]`</br>
     
     - And if we porceed we will find that all the remaing fields doesn't need any modification.

     - As `H` is 2 byte unsigned short and `4s` is 4 byte unsigned int 
           
