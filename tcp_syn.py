"""

 TCP SYN scan
 nmap flag: -sS

"""

import socket

from impacket import ImpactPacket, ImpactDecoder
from impacket.ImpactPacket import TCP

src = '10.0.2.15'
dst = '10.0.2.5'

sport = 12345  # Random source port
dport = 80  # Port that we want to probe

# Create a new IP packet and set its source and destination addresses.

# Construct the IP Packet
ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(dst)

# Construct the TCP Segment
tcp = ImpactPacket.TCP()
tcp.set_th_sport(sport)  # Set the source port in TCP header
tcp.set_th_dport(dport)  # Set the destination in TCP header
tcp.auto_checksum = 1
# Set the SYN flag bit for the 1st step of 3-way handshake
tcp.set_SYN()



# Put the TCP Segment into the IP Packet
ip.contains(tcp)


'''
We are using Raw sockets here because if we use a Stream socket, 
then we'll have to use the connect() method which will internally make a TCP 3-way handshake.
The prerequisite for sending any data through a Stream socket is that it should be in a 'connected' state.
As we want to have full control over TCP handshake process, we're using a Raw socket and that requires root privileges.
'''
# Create a Raw Socket to send the above constructed Packet
# socket(<domain>, <type>, <protocol>)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)  # protocol value can also be fetched like this: socket.getprotobyname('tcp')
# For a full list of protocol values that can be passed, refer:
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

'''
Question: Why do we have to mention the protocol number if we're creating a Raw socket?
First of all, doesn't matter what socket type we're using, we HAVE to pass in what Transport layer protocol we'll be using.
Because, the python socket() function internally calls the socket(<domain>, <type>, <protocol>) syscall which takes in the 3 arguments.
Raw socket simply allows access to network protocol headers. But it has to be associated with a transport protocol. That's why we mention the protocol number.
Also, this transport layer protocol number is part of the IPv4 headers as well!
'''


# The below method is to set some socket options
# we're enabling IP_HDRINCL by setting it to 1
# This tells the kernel that we will be including the IP headers ourselves
# Normally, IP headers are included by the kernel and if IP_HDRINCL option is enabled,
# IP headers are not included by the kernel
# IP_HDRINCL probably stands for "IP Header Included" which tells the kernel that
# the user has already included the IP headers
# setsockopt(<protocol-level>, <option-name>, <option-value>)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# calls sendto() syscall
s.sendto(ip.get_packet(), (dst, 0))

# UNCOMMENT BELOW LINE IF src AND dst ARE 127.0.0.1
# packet = s.recvfrom(4096)[0]  # This will show the packet sent from sender to receiver.
packet = s.recvfrom(4096)[0]  # This is the packet we're interested in. Receiver to sender packet

# Decode the received Packet
res_ip = ImpactDecoder.IPDecoder().decode(packet)
res_tcp: TCP = res_ip.child()  # Get the response TCP Segment from the IP Packet
'''
### TCP Flags Explained ###
1. URG: Urgent Pointer: This flag indicates that the receiver doesn't have to wait for the previous segment.
                     The packet with this flag is processed by the receiver immediately.
2. ACK: Acknowledge flag: Used to acknowledge the successful receipt of packets
3. PSH: Push flag: If used, it indicates that the sender or receiver needs to give priority to the segment.
                It is normally used at the beginning and at the end of the data transfer.
4. RST: Reset flag: When a segment arrives with this flag, it means that there was no service awaiting for the sender
                    for the requested port and protocol. Hence the receiver asks the sender to reset their connection 
                    and maybe request for a different connection.
5. SYN: Synchronization flag: This flag is initially used when establishing a 3-way handshake. The most wellknown
                              TCP flag
6. FIN: Finish flag: Used when terminating an active connection. 

Flag format:
URG-ACK-PSH-RST-SYN-FIN
Example, if flag bits are: 
010100
Then that means ACK and RST flags are set.

We can get the flag bits in this code like following:
'''

print("Pretty print the IP Packet:")
print(res_ip)

print("Flag bit format: URG-ACK-PSH-RST-SYN-FIN")
print("Request Flag bits: " + bin(tcp.get_th_flags())[2:].zfill(6))
flag_bits = bin(res_tcp.get_th_flags())[2:].zfill(6)
print("Response Flag bits: " + flag_bits)
# Flag format: URG-ACK-PSH-RST-SYN-FIN
# if SYN/ACK are set
if flag_bits == '010010':
    print('%d is open' % dport)
# if RST/ACK are set
elif flag_bits == '010100':
    print('%d is closed' % dport)

s.close()

'''
Problems:
This code always sends a TCP Segment with RST flag set to the receiver.
It is done by the OS and not the code.
nmap doesn't do that. 
I don't know how to stop sending RST flag from my code.
'''