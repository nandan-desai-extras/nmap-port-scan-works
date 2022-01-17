# Nmap Port Scanning Techniques

This project tries to implement the port scanning concepts described in the "Nmap Network Scanning" book. You can find the online version of the book [here!](https://nmap.org/book/) Book index can be found [here!](https://nmap.org/book/toc.html)

This project tries to cover the 5th Chapter of the book titled "Port Scanning Techniques and Algorithms". Although we don't cover the entire chapter and skip the Algorithms and SCTP and FTP techniques, we do cover all of the TCP and UDP port scanning techniques mentioned in the book.

The code uses [Impacket](https://github.com/SecureAuthCorp/impacket) library to create and manipulate the IP, TCP, ICMP and UDP packets. 

## The Purpose of this project

The purpose of this project is to give you an idea about how each of those scanning techniques work. The explanation given in the Nmap book is converted into Python code here. As simple as that. Once you understand this code, you will know what Nmap is doing under the hood while it's scanning for ports.

If you wanna start reading the code, we suggest that you read the code in the following order:

 1. [tcp_connect.py](/blob/main/tcp_connect.py)
 2. [tcp_syn.py](/blob/main/tcp_syn.py)
 3. [tcp_null_fin_xmas.py](/blob/main/tcp_null_fin_xmas.py)
 4. [tcp_maimon.py](/blob/main/tcp_maimon.py)
 5. [tcp_ack.py](/blob/main/tcp_ack.py)
 6. [tcp_window.py](/main/tcp_window.py)
 7. [tcp_idle.py](/blob/main/tcp_idle.py)
 8. [udp_scan.py](/blob/main/udp_scan.py)
 9. [ip_protocol_scan.py](/blob/main/ip_protocol_scan.py)

You can view more details on each of these techniques here: https://nmap.org/book/man-port-scanning-techniques.html

Here is a diagram to (kind of) summarize some of the TCP port scanning techniques:

![nmap tcp port scanning techniques](https://raw.githubusercontent.com/NandanDesai/res/master/nmap-scan.jpg)

## License

MIT License

Copyright 2022 Nandan Desai

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

