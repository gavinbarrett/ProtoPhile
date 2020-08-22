#!/usr/bin/env python3
import sys
import tty
import struct
import socket
import termios
import asyncio
from binascii import hexlify

# create socket objects
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

YELLOW = '\u001b[33m'
GREEN = '\u001b[32m'
WHITE = '\u001b[37m'
CYAN = '\u001b[36m'
BLUE = '\u001b[34m'
RED = '\u001b[31m'

def unpack_ip(ip_header):
	return struct.unpack("!BBHHHBBH4s4s", ip_header)

def unpack_eth(eth_header):
	return struct.unpack("!8s6s6s2s", eth_header)

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

async def read_socket(sock, i):
	# receive tuple of data and ...
	packet = sock.recvfrom(65536)
	# grab network data
	packet = packet[0]
	# strip out ip header
	ip_head = packet[0:20]
	eth_head = packet[0:22]
	data = packet[24:]
	iph = unpack_ip(ip_head)
	eth = unpack_eth(eth_head)
	packet_type = get_packet_type(iph[6])
	# extract version
	x = (iph[0] >> 4) & 0x0F
	# retrieve the src and dest hostnames
	src_host = host_lookup(socket.inet_ntoa(iph[8]))
	dest_host = host_lookup(socket.inet_ntoa(iph[9]))
	if packet_type == 'TCP':
		COLOR = GREEN
	else:
		COLOR = CYAN
	print(f"{WHITE}#{i}: {COLOR}{packet_type}{WHITE} - {YELLOW}[{BLUE}{src_host}{WHITE} {YELLOW}\u2192 {RED}{dest_host}{WHITE} {YELLOW}]{WHITE}")
	print(data)

# set up - read command line args from sys.argv
async def main():
	i = 0
	while True:
		await read_socket(tcp_sock, i)
		i += 1
		await read_socket(udp_sock, i)
		i += 1

asyncio.run(main())
