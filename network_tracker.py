import tty
import struct
import socket
import termios

# create socket object
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

GREEN = '\u001b[32m'
WHITE = '\u001b[37m'
CYAN = '\u001b[36m'
def handle_tcp():
	print("Encountered TCP packet")

def handle_udp():
	print("Encountered UDP packet")

def unpack_ip(ip_header):
	return struct.unpack("!BBHHHBBH4s4s", ip_header)

def get_packet_type(pack_type):
	if pack_type == 6:
		return 'TCP'
	elif pack_type == 17:
		return 'UDP'
	else:
		print(f'Unknown packet type: {pack_type}')
		return 'Unknown'

def host_lookup(addr):
	try:
		# try to retrieve the host name
		host = socket.gethostbyaddr(addr)
		return host[0]
	except:
		return addr

def read_socket(sock, i):
	# receive tuple of data and ...
	packet = sock.recvfrom(65536)
	# grab network data
	packet = packet[0]
	# strip out ip header
	ip_head = packet[0:20]
	data = packet[24:]
	#print(f"ip_head: {ip_head}\n")
	# unpack bytes of ip_header
	iph = unpack_ip(ip_head)
	#if iph[6] == 6:
	#	handle_tcp()
	#elif iph[6] == 17:
	#	handle_udp()
	packet_type = get_packet_type(iph[6])

	x = (iph[0] >> 4) & 0x0F
	#print(f"Version: {x}")
	#print(f"Total Length: {iph[2]}")
	#print(f"Protocol: {iph[6]}")
	#print(f"Header checksum: {iph[7]}")
	# print source and destination ips
	src = socket.inet_ntoa(iph[8])
	# retrieve the src and dest hostnames
	src_host = host_lookup(socket.inet_ntoa(iph[8]))
	dest_host = host_lookup(socket.inet_ntoa(iph[9]))
	
	if packet_type == 'TCP':
		COLOR = GREEN
	else:
		COLOR = CYAN
	print(f"{WHITE} #{i}: {COLOR}{packet_type}{WHITE} - {src_host} \u2192 {dest_host}")

i = 0
while True:
	read_socket(s, i)
	i += 1
	read_socket(s2, i)
	i += 1	
	#print(f"Packet Data:\n{data}\n")
