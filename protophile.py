#!/usr/bin/env python3
import sys
import tty
import struct
import socket
import termios
import asyncio
import argparse
from binascii import hexlify

# read all packets captured
sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
# bind to wireless interface
sock.bind(('wlp2s0', 0))

YELLOW = '\u001b[33m'
GREEN = '\u001b[32m'
WHITE = '\u001b[37m'
CYAN = '\u001b[36m'
BLUE = '\u001b[34m'
RED = '\u001b[31m'
END = '\033[0m'

def unpack_ip(ip_header):
	''' Interpret the bytes as an IP header '''
	# unpack byte stream
	ip_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
	#
	version = ip_data[0]
	#
	service_type = ip_data[1]
	# save length
	length = ip_data[2]
	# save source address
	src = socket.inet_ntoa(ip_data[8])
	# save destination address
	dest = socket.inet_ntoa(ip_data[9])

	return version, dest, src

def unpack_eth(eth_header):
	''' Interpret the bytes as an Eth header '''
	# unpack the ethernet packet
	ether = struct.unpack('!6s6s2s', eth_header)
	# extract the destination mac
	dest_mac = format_mac(ether[0].hex())
	# extract the src mac address
	src_mac = format_mac(ether[1].hex())
	# extract the protocol
	protocol = ether[2].hex()
	return dest_mac, src_mac, protocol

def unpack_tcp(tcp_packet):
	''' Interpret the bytes as a TCP packet '''
	tcp = struct.unpack('!HHLLBBHHH', tcp_packet)
	src_port = tcp[0]
	dest_port = tcp[1]
	return dest_port, src_port

def unpack_udp(udp_packet):
	''' Interpret the bytes as a UDP packet '''
	return struct.unpack('!HHHH', udp_packet)

def unpack_data(pack_type):
	if pack_type == 6:
		return 'TCP'
	elif pack_type == 17:
		return 'UDP'
	else:
		print(f'Unknown packet type: {pack_type}')
		return 'Unknown'

def format_mac(mac):
	''' Format the MAC address with hyphens '''
	mac = mac.upper()
	return ''.join([f'{mac[i:i+2]}-' if i < 10 else f'{mac[i:i+2]}' for i in range(0, len(mac), 2)])

def host_lookup(addr):
	try:
		# try to retrieve the host name
		host = socket.gethostbyaddr(addr)
		return host[0]
	except:
		return addr

async def read_socket(idx):
	# receive tuple of data and ...
	packet = sock.recvfrom(65536)
	# grab network data
	packet_data, addr = packet
	# extract MAC info
	dest_mac, src_mac, proto = unpack_eth(packet_data[0:14])
	# extract IP info
	version, dest_ip, src_ip = unpack_ip(packet_data[14:34])
	
	# extract TCP/UDP/ICMP packet data
	dest_port, src_port = unpack_tcp(packet_data[34:54])
	print(f'{END}{idx}| {BLUE}{src_ip}:{src_port}{END}[{YELLOW}{src_mac}{END}] {YELLOW}\u2192 {RED}{dest_ip}:{dest_port}{END}[{YELLOW}{dest_mac}{END}]')

async def listen():
	for i in range(1, 10):
		await read_socket(i)

if __name__ == "__main__":
	asyncio.run(listen())
