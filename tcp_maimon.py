"""

 TCP Maimon scans
 nmap flags: -sM

"""

import socket

from impacket import ImpactPacket, ImpactDecoder
from impacket.ImpactPacket import TCP

src = '10.0.2.15'
dst = '10.0.2.4'

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

# Set FIN/ACK
tcp.set_FIN()
tcp.set_ACK()


# Put the TCP Segment into the IP Packet
ip.contains(tcp)

# Create a Raw Socket to send the above constructed Packet
# socket(<domain>, <type>, <protocol>)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                  6)  # protocol value can also be fetched like this: socket.getprotobyname('tcp')
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# calls sendto() syscall
s.sendto(ip.get_packet(), (dst, 0))

s.settimeout(3)
# UNCOMMENT BELOW LINE IF src AND dst ARE 127.0.0.1
# packet = s.recvfrom(4096)[0]  # This will show the packet sent from sender to receiver.
try:
    '''
    
    On most systems, we'll get an RST packet as response for both open and closed ports.
    However, BSD-derived systems seem to work for this scan. They just drop the packet if the port is open
    and respond with RST if it's closed.
    
    '''
    packet = s.recvfrom(4096)[0]  # This is the packet we're interested in. Receiver to sender packet
except socket.timeout:
    print('%d is open|filtered' % dport)
    exit(0)

# Decode the received Packet
res_ip = ImpactDecoder.IPDecoder().decode(packet)
res_tcp: TCP = res_ip.child()  # Get the response TCP Segment from the IP Packet

print("Pretty print the IP Packet:")
print(res_ip)

print("Flag bit format: URG-ACK-PSH-RST-SYN-FIN")
print("Request Flag bits: " + bin(tcp.get_th_flags())[2:].zfill(6))
flag_bits = bin(res_tcp.get_th_flags())[2:].zfill(6)
print("Response Flag bits: " + flag_bits)

# Flag format: URG-ACK-PSH-RST-SYN-FIN
# if RST are set
if flag_bits == '000100':
    print('%d is closed' % dport)

s.close()
