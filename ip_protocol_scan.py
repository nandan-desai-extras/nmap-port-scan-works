"""

 IP protocol scan
 nmap flags: -sO

"""

import select
import socket

from impacket import ImpactPacket, ImpactDecoder
from impacket.ImpactPacket import ICMP

src = '10.0.2.15'
dst = '10.0.2.4'

# Change the value to whatever protocol we wanna test.
# Find the full list of protocol numbers here:
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
protocol_number = 7

# Create a new IP packet and set its source and destination addresses.

# Construct the IP Packet
ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(dst)

# Set the protocol number in IPv4 header
ip.set_ip_p(protocol_number)

'''
This scan is similar to UDP scan.
We'll use UDP socket to transmit our IP packet. 
'''

# Create a Raw Socket to send the above constructed Packet
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('udp'))
udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

udp_socket.settimeout(3)
udp_socket.sendto(ip.get_packet(), (dst, 0))

# List of sockets from which we expect to receive some kind of response
socket_list = [udp_socket, icmp_socket]

# udp_socket.recvfrom(4096)[0] # Read and discard our own UDP packet from sender to receiver

# Select the sockets from the socket_list which have some response for us
read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

for sock in read_sockets:
    if sock == icmp_socket:
        print('ICMP socket has a response for us')
        packet = sock.recvfrom(4096)[0]
        res_ip = ImpactDecoder.IPDecoder().decode(packet)
        icmp: ICMP = res_ip.child()
        print('ICMP Type: ' + str(icmp.get_icmp_type()))
        print('ICMP Code: '+str(icmp.get_icmp_code()))
        # ICMP Error Code 3 is port unreachable error. That means the protocol exists!
        if icmp.get_icmp_type() == 3 and icmp.get_icmp_code() == 3:
            print('Protocol number %d is open!' % protocol_number)
        # ICMP Error Code 2 is protocol unreachable error
        elif icmp.get_icmp_type() == 3 and icmp.get_icmp_code() == 2:
            print('Protocol number %d is closed!' % protocol_number)
        else:
            # Any other ICMP Error Code means the protocol is filtered
            print('Protocol number %d is filtered!' % protocol_number)
    elif sock == udp_socket:
        print('UDP socket has a response for us')
        packet = sock.recvfrom(4096)[0]
        res_ip = ImpactDecoder.IPDecoder().decode(packet)
        print(res_ip)
    else:
        print('Some other type of socket has a response for us')
        packet = sock.recvfrom(4096)[0]
        res_ip = ImpactDecoder.IPDecoder().decode(packet)
        print(res_ip)

icmp_socket.close()
udp_socket.close()

'''
During my tests, the supported protocols didn't have any responses while the non-supported protocols gave
ICMP Error Code 2.
'''