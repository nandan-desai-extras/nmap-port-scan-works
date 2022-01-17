"""

 UDP scan
 nmap flags: -sU

"""

import select
import socket
from impacket import ImpactPacket, ImpactDecoder
from impacket.ImpactPacket import ICMP

src = '10.0.2.15'
dst = '10.0.2.4'

sport = 12345  # Random source port
dport = 9000 # Port that we want to probe

# Create a new IP packet and set its source and destination addresses.

# Construct the IP Packet
ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(dst)

udp = ImpactPacket.UDP()
udp.set_uh_sport(sport)
udp.set_uh_dport(dport)
udp.auto_checksum = 1

ip.contains(udp)

# Create a Raw Socket to send the above constructed Packet
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('udp'))
udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Send the UDP packet
udp_socket.settimeout(3)
udp_socket.sendto(ip.get_packet(), (dst, 0))

# List of sockets from which we expect to receive some kind of response
socket_list = [udp_socket, icmp_socket]

# Select the sockets from the socket_list which have some response for us
read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

for sock in read_sockets:
    if sock == icmp_socket:
        '''
        Linux hosts have rate-limiting for ICMP responses. Which is 1 ICMP response/second.
        So we can't just bombard UDP segments to the target and expect to get ICMP response.
        (I think this can be used to fingerprint the OS as the Nmap doc says that this is done by Linux.)
        '''
        print('ICMP socket has a response for us')
        packet = sock.recvfrom(4096)[0]
        res_ip = ImpactDecoder.IPDecoder().decode(packet)
        icmp: ICMP = res_ip.child()
        print('ICMP Type: ' + str(icmp.get_icmp_type()))
        print('ICMP Code: '+str(icmp.get_icmp_code()))
        if icmp.get_icmp_type() == 3 and icmp.get_icmp_code() == 3:
            print('Port '+str(dport)+' is closed!')
        elif icmp.get_icmp_type() == 3 and icmp.get_icmp_code() != 3:
            print('Port '+str(dport)+' is filtered!')
    elif sock == udp_socket:
        # This happens occasionally in certain rare cases
        print('UDP socket has a response for us')
        print('Port '+str(dport)+' is open!')
        packet = sock.recvfrom(4096)[0]
        res_ip = ImpactDecoder.IPDecoder().decode(packet)
        print(res_ip)
    else:
        # ???
        print('Some other type of socket has a response for us')
        packet = sock.recvfrom(4096)[0]
        res_ip = ImpactDecoder.IPDecoder().decode(packet)
        print(res_ip)

icmp_socket.close()
udp_socket.close()
