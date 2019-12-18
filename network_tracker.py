import struct
import socket

# create socket object
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

def handle_tcp():
	print("Encountered TCP packet")

def handle_udp():
	print("Encountered UDP packet")

def unpack_ip(ip_header):
	return struct.unpack("!BBHHHBBH4s4s", ip_header)

i = 0
for i in range(0, 20):
	# receive tuple of data and ...
	packet = s.recvfrom(65536)
	# grab network data
	packet = packet[0]
	# strip out ip header
	ip_head = packet[0:20]
	data = packet[24:]
	#print(f"ip_head: {ip_head}\n")
	# unpack bytes of ip_header
	iph = unpack_ip(ip_head)
	if iph[6] == 6:
		handle_tcp()
	elif iph[6] == 17:
		handle_udp()
	x = (iph[0] >> 4) & 0x0F
	print(f"Version: {x}")
	print(f"Total Length: {iph[2]}")
	print(f"Protocol: {iph[6]}")
	print(f"Header checksum: {iph[7]}")
	# print source and destination ips
	src = socket.inet_ntoa(iph[8])
	try:
		src = socket.gethostbyaddr(src)[0]
	except:
		print('src hostname could not be found')
	print(src)
	print(f"Source:	  {socket.inet_ntoa(iph[8])}")
	print(f"Destination: {socket.inet_ntoa(iph[9])}")
	print(f"Packet Data:\n{data}\n")
