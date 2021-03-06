#!/usr/bin/env python3
import sys
import tty
import time
import struct
import socket
import termios
import asyncio
import argparse
from datetime import date
from binascii import hexlify

# read all packets captured
sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
# bind to wireless interface
sock.bind(('wlp2s0', 0))

YELLOW = '\u001b[33m'
GREEN = '\u001b[32m'
WHITE = '\u001b[37m'
CYAN = '\u001b[36m'
BLUE = '\u001b[34m'
RED = '\u001b[31m'
END = '\033[0m'

def print_header():
	''' Print ProtoPhile header '''
	print("   ___           _          ___ _     _ _      \n  / _ \_ __ ___ | |_ ___   / _ \ |__ (_) | ___ \n / /_)/ '__/ _ \| __/ _ \ / /_)/ '_ \| | |/ _ \\\n/ ___/| | | (_) | || (_) / ___/| | | | | |  __/\n\/    |_|  \___/ \__\___/\/    |_| |_|_|_|\___|")

def unpack_ip(ip_header):
	''' Interpret the bytes as an IP header '''
	# unpack byte stream
	ip_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
	# extract version number
	version = ip_data[0] >> 4
	ihl = version & 0x0f
	iph_length = ihl * 4
	# extract service type
	service_type = ip_data[1]
	# save length
	length = ip_data[2]
	# save source address
	src = socket.inet_ntoa(ip_data[8])
	# save destination address
	dest = socket.inet_ntoa(ip_data[9])
	protocol = ip_data[6]
	return version, dest, src, protocol, iph_length

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
	#print(f'Src: {src_port}\nDest: {dest_port}')
	data = ''
	return dest_port, src_port

def unpack_udp(udp_packet):
	''' Interpret the bytes as a UDP packet '''
	udp = struct.unpack('!HHHH', udp_packet)
	src_port = udp[0]
	dest_port = udp[1]
	data = ''
	return src_port, dest_port

def get_proto(proto):
	if proto == 1:
		return 'ICMP'
	elif proto == 6:
		return 'TCP'
	elif proto == 17:
		return 'UDP'
	else:
		return 'UNK'

def unpack_data(protocol, data, iph):
	if protocol == 1:
		# ICMP Packet
		return ("ICMP", "ICMP")
	elif protocol == 6:
		# TCP Packet
		return unpack_tcp(data[34:54])
	elif protocol == 17:
		# UDP Packet
		return unpack_udp(data[34:42])
	elif protocol == 50:
		# Encapsulation Security Payload
		#print('ESP Packet encountered')
		return (None, None)
	elif protocol == 51:
		# Authentication Header
		#print('AH Packet encountered')
		return (None, None)
	else:
		#print(f'Unknown packet type: Protocol #{protocol}')
		return (None, None)

def format_mac(mac):
	''' Format the MAC address with hyphens '''
	# convert chars to uppercase
	#mac = mac.upper()
	# insert hyphens
	return ''.join([f'{mac[i:i+2]}:' if i < 10 else f'{mac[i:i+2]}' for i in range(0, len(mac), 2)])

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
	version, dest_ip, src_ip, protocol, iph_length = unpack_ip(packet_data[14:34])
	
	# extract TCP/UDP/ICMP packet data
	dest_port, src_port = unpack_data(protocol, packet_data, iph_length)
	
	if dest_port == "ICMP" and src_port == "ICMP":
		print(f'{BLUE}{src_ip : <15}{END}[{src_mac}{END}] {get_proto(protocol)}  {YELLOW}\u27f9   {RED}{dest_ip : <15}{END}[{dest_mac}{END}]')
	elif dest_port and src_port:
		src = f'{src_ip}:{END}{src_port}'
		dest = f'{dest_ip}:{END}{dest_port}'
		print(f'{BLUE}{src : <25}[{CYAN}{src_mac}{END}] {get_proto(protocol)}  {YELLOW}\u27f9   {RED}{dest : <25}[{CYAN}{dest_mac}{END}]')
		
		#print(f'{END}{idx}| {BLUE}{src_ip : <15}:{YELLOW}{src_port : <5}{END}[{src_mac}{END}] {get_proto(protocol)}  {YELLOW}\u2192  {RED}{dest_ip : >15}:{YELLOW}{dest_port : >5}{END}[{dest_mac}{END}]')

async def listen():
	idx = 1
	while True:
		await read_socket(idx)
		idx += 1


if __name__ == "__main__":
	# Print ProtoPhile header
	print_header()
	# Print packet capture start time
	print(f'Starting packet capture at {time.strftime("%I:%M:%S %p on %b %d %Y")}')
	# Run packet capture until program is killed
	asyncio.run(listen())
