"""

 TCP NULL, FIN, and Xmas scans
 nmap flags: -sN; -sF; -sX

"""

import socket

from impacket import ImpactPacket, ImpactDecoder
from impacket.ImpactPacket import TCP

src = '10.0.2.15'
dst = '10.0.2.4'

sport = 12345  # Random source port
dport = 81  # Port that we want to probe

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

# NULL
#######

# FIN
# tcp.set_FIN()

# Light up the Xmas tree
tcp.set_URG()
tcp.set_PSH()
tcp.set_FIN()


# Put the TCP Segment into the IP Packet
ip.contains(tcp)

# Create a Raw Socket to send the above constructed Packet
# socket(<domain>, <type>, <protocol>)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)  # protocol value can also be fetched like this: socket.getprotobyname('tcp')
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# calls sendto() syscall
s.sendto(ip.get_packet(), (dst, 0))

s.settimeout(3)
# UNCOMMENT BELOW LINE IF src AND dst ARE 127.0.0.1
# packet = s.recvfrom(4096)[0]  # This will show the packet sent from sender to receiver.
try:
    '''
    If the port is open and if SYN, RST or ACK bits are not set,
    then the packet will be dropped. Hence, if we don't set SYN, RST or ACK bits 
    and don't receive any response, then port is open. (Or it can be filtered as well)
    
    If port is closed, then we'll receive RST/ACK.
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
# if RST/ACK are set
if flag_bits == '010100':
    print('%d is closed' % dport)

s.close()

'''
This scan doesn't work on Windows as it returns RST regardless of whether the port is open or closed during this scan.
(This can be one factor when we want to find out the type of the OS of the target).
If we get RST for all ports of the target during this scan, then there is a high chance that the target is running Windows.
Also note that many Cisco devices, BSDI, IBM OS/400 behave the same way as Windows during this scan.

Note: In my personal test, Windows 10 with port 80 open, didn't send any response for this scan neither for open nor closed ports
Might be due to Windows Firewall. 
Linux worked as expected.
'''