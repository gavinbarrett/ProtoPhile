import struct
import socket

# create socket object
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

i = 0
for i in range(0, 5):
    # receive tuple of data and ...
    packet = s.recvfrom(65565)
    # grab network data
    packet = packet[0]
    # strip out ip header
    ip_head = packet[0:20]
    # unpack bytes of ip_header
    iph = struct.unpack('!BBHHHBBH4s4s', ip_head)
    # print source and destination ips
    print(socket.inet_ntoa(iph[8]))
    print(socket.inet_ntoa(iph[9]))
