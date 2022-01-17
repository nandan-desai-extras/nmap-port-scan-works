"""

 TCP Idle scan
 nmap flags: -sI

 This script is based on the following article:
 https://nmap.org/book/idlescan.html


"""

import socket
import time
from impacket import ImpactPacket, ImpactDecoder
from impacket.ImpactPacket import TCP

src = '10.0.2.15'  # Ubuntu 20.04.3 LTS
zombie = '10.0.2.6'  # Windows XP SP3
target = '10.0.2.4'  # Parrot 4.11 64-bit

sport = 12345  # Random source port
dport = 80  # Port that we want to probe

'''
Step 1: Send a SYN/ACK to get the initial IP ID of the Zombie
'''
print("* Starting Step 1 of the TCP Idle Scan")
# Construct the IP Packet for Zombie
ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(zombie)

# Construct the TCP Segment
tcp = ImpactPacket.TCP()
tcp.set_th_sport(sport)  # Set the source port in TCP header
tcp.set_th_dport(dport)  # Set the destination port in TCP header
tcp.auto_checksum = 1
# Set the SYN/ACK flag bit
tcp.set_SYN()
tcp.set_ACK()

# Put the TCP Segment into the IP Packet
ip.contains(tcp)

# Create a Raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Send the packet to Zombie
s.sendto(ip.get_packet(), (zombie, 0))

packet = s.recvfrom(4096)[0]
res_ip = ImpactDecoder.IPDecoder().decode(packet)
res_tcp: TCP = res_ip.child()
flag_bits = bin(res_tcp.get_th_flags())[2:].zfill(6)

initial_IP_ID = 0

# Flag format: URG-ACK-PSH-RST-SYN-FIN
# if RST is set
if flag_bits == '000100':
    print("* As expected, Zombie sent an RST.")
else:
    print("* Zombie didn't send an RST. That's unexpected. The response flags is %s and 000100 was expected instead" % flag_bits)
# Capture the initial IP ID of the Zombie
initial_IP_ID = res_ip.get_ip_id()
print('* Initial Zombie IP ID: %d' % initial_IP_ID)


#######################################################################
'''
Step 2: Forge a SYN packet that appears to be coming from Zombie to the Target
'''
print("* Starting Step 2 of the TCP Idle Scan")
# Construct the fake IP Packet for the Target
ip = ImpactPacket.IP()
ip.set_ip_src(zombie)
ip.set_ip_dst(target)

# Construct the TCP Segment
tcp = ImpactPacket.TCP()
tcp.set_th_sport(sport)  # Set the source port in TCP header
tcp.set_th_dport(dport)  # Set the destination port in TCP header
tcp.auto_checksum = 1
# Set the SYN flag bit
tcp.set_SYN()

# Put the TCP Segment into the IP Packet
ip.contains(tcp)

# Send the packet to Target
s.sendto(ip.get_packet(), (target, 0))

print("* Sleeping for 2 seconds to allow the Target send it's response to Zombie")
time.sleep(2)



#######################################################################
'''
Step 3: Probe the IP ID of the Zombie again
'''
print("* Starting Step 3 of the TCP Idle Scan")
# Construct the IP Packet for Zombie
ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(zombie)

# Construct the TCP Segment
tcp = ImpactPacket.TCP()
tcp.set_th_sport(sport)  # Set the source port in TCP header
tcp.set_th_dport(dport)  # Set the destination port in TCP header
tcp.auto_checksum = 1
# Set the SYN/ACK flag bit
tcp.set_SYN()
tcp.set_ACK()

# Put the TCP Segment into the IP Packet
ip.contains(tcp)

# Send the packet to Zombie
s.sendto(ip.get_packet(), (zombie, 0))

packet = s.recvfrom(4096)[0]
res_ip = ImpactDecoder.IPDecoder().decode(packet)
res_tcp: TCP = res_ip.child()
flag_bits = bin(res_tcp.get_th_flags())[2:].zfill(6)

if flag_bits == '000100':
    print("* As expected, Zombie sent an RST.")
else:
    print("* Zombie didn't send an RST. The response flags is "+flag_bits)

updated_IP_ID = res_ip.get_ip_id()
print('* Updated Zombie IP ID: %d' % updated_IP_ID)
# Get the IP ID difference
IP_ID_diff = updated_IP_ID - initial_IP_ID
if IP_ID_diff == 2:
    print('!!! Port %d of the target is open' % dport)
elif IP_ID_diff == 1:
    print('!!! Port %d of the target is closed' % dport)
else:
    print('??? IP ID difference is unexpected (%d). The Zombie might be having some other network traffic going on' % IP_ID_diff)
    print('* Try re-running this script again.')

'''
In the real world, searching for a Zombie machine is a herculean task in my opinion. 
The machine should have a global IP ID and should increase by 1 for every packet 
and should have little to no network activity on it.

We can use the following nmap command to find the IP ID Sequence Generation on a machine:
sudo nmap -O -v <ip>
just use -v when doing OS detection and if we get 'IP ID Sequence Generation' as 'Incremental', then that is 
the suitable Zombie for us.
'''