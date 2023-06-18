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

     - As `H` is 2 byte unsigned short and `4s` is 4 byte unsigned int.


## The IP Decoder
This script is responsible for decoding the IP header of network packets. It extracts various fields from the header, such as the version, Internet Header Length (IHL), Type of Service (TOS), length, identification, offset, Time to Live (TTL), protocol number, checksum, source address, and destination address.</br>

-  ### Implementation Details

     - `IP` class: This class represents an IP packet and is used to decode the IP header. It takes a binary buffer as input and unpacks the data according to the IP header structure. The individual            fields are extracted and stored as attributes in the class instance. The source and destination addresses are converted to human-readable IP addresses using the `ipaddress` module. The protocol          number is mapped to its corresponding protocol name using a dictionary lookup.

     - `sniff` function: This function is responsible for sniffing network packets and printing the detected protocol and hosts. It creates a raw socket for sniffing and sets the socket options                 accordingly. It then enters an infinite loop where it reads a packet, creates an `IP` instance from the first 20 bytes of the packet, and prints the protocol type, source address, and destination         address.
           

## Decoding ICMP
First we need to know how the Destination Unreachable ICMP message looks like:
![Screenshot from 2023-06-18 22-26-04](https://github.com/MoAli-sec/UDP-Host-Discovery/assets/73645329/e001e75b-ed8f-44cc-aa76-e2fd8139c59f)

We will use the struct module to decode it and it follows the same approach as decoding the IP

But the only difference is you have to extract it first and you that calculate the value of the `offset` variable as you should know the ICMP message starts in the `IP.ihl (Header length) * 4`

The script `icmp_sniffer.py` demos the idea of how it works.

## The Scanner
The Script `scanner.py` is the sum of all the codes we wrote before as it uses all the techniques we implemented previously to discover the hosts on the network.

This network scanner is a Python script that detects hosts up in a specified subnet using ICMP packets. It sends UDP datagrams with a magic message to all hosts in the subnet and listens for ICMP responses to identify hosts that are up.


# Requirements
To run any of these scripts, ensure you have the following:
- Python3.x

- All the modules are pre-installed with python


# Usage
Note that any IP addresses might vary according to your location and your network subnet mask and you might need to modify the code a bit if you have a different subnet.


Also, Note that you might need to run the script with administrator privileges as we are interacting with low-level network protocols, So consider using sudo with Linux and macOS.
```
sudo python script.py
```

On Windows you will need to start the cmd or PowerShell with administrator privileges by right click on it then choose run as administrator

- ### ip_packet_capture.py
     After you open your terminal you can run the following

     ```
     sudo python ip_packet_capture.py
     ```

     In another terminal run a ping to any website for example google.com:

     ```
     ping google.com
     ```

     The Output should be like:
     
     ```
     (b'E\x00\x00T\x00\x00\x00\x00v\x01\xce\xd5\x8e\xfb%.\xc0\xa8\x01\x02\x00\x00q\x7f\xdbt\x00\x01\xe6`\x8fd\x00\x00\x00\x00xr\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', ('142.251.37.46', 0))
     ```

- ### ip_header_ctypes.py
     This script will take the previous output and give us a readble IPs

     I added an Example of usage on the script you can uncomment it to test the results
     
     After you open your terminal you can run the following

     ```
     sudo python ip_header_ctypes.py
     ```

- ### ip_header_struct.py
     This script will take the previous output and give us a readble IPs

     I added an Example of usage on the script you can uncomment it to test the results

     After you open your terminal you can run the following

     ```
     sudo python ip_header_struct.py
     ```

- ### network_traffic_sniffer.py
     This script keep sniffing the network and print the output of the decoding

     In this script the output will very on Windows and Linux

     Running on Windows

     ```
     python network_traffic_sniffer.py
     ```

     Now, because Windows is pretty chatty, you're likely to see output immediatlly

     Running on Linux

     ```
     sudo python network_traffic_sniffer.py
     ```

     To get output here you will have to ping any website also in another terminal

     ```
     ping google.com
     ```

- ### icmp_sniffer.py
     Is the same as `network_traffic_sniffer.py` but with the addition of decoding the ICMP and extracting some additional values from it.


- ### scanner.py
     This script you can run it on any OS and it will give you the same results which is the hosts that are up on your network

     ```
     sudo python scanner.py
     ```

# Disclaimer
This tool is intended for educational and testing purposes only. Please use responsibly and with the explicit permission of the network owner. Use them at your own risk.

# License
This project is licensed under the MIT License.

Feel free to modify and extend the code according to your needs.
