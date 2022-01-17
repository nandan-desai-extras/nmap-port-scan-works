"""

 TCP Connect scans
 nmap flags: -sT

"""

import socket

dst = '10.0.2.4'
dport = 8080  # Port that we want to probe

# Python uses TCP whenever we create a Stream socket.
# Stream socket ensures reliability of the data transfered through it.
# But TCP is not the only 'reliable' protocol for Stream socket. SCTP is another newer one.
# That '6' stands for TCP. These numbers are standard and we can see the full list here: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
# Other useful links: Socket() syscall manpage: https://man7.org/linux/man-pages/man2/socket.2.html
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 6)
s.settimeout(3)  # 3 seconds timeout
try:
    s.connect((dst, dport))  # Uses connect() syscall
    print('Port open: ' + str(dport))
except ConnectionRefusedError:
    print('Port not open: ' + str(dport))
except socket.timeout:
    print('Host not reachable')

'''
TCP Connect scan is not very stealthy as it tries to do a 3-way handshake with every port.
And also becomes slow when we want to scan all the ports on a host.
Hence, TCP SYN scan is preferred as it pretends to start a 3-way handshake,
but never completes it and hence is a bit stealthy and also can distinguish between open/closed/filtered ports.
'''