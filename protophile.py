#!/usr/bin/env python3
import os
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


# wlp2s0 (wireless), enp0s31f6 ()

# wlp0s20f0u1

# beautiful terminal colors
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
	return version, src, dest, protocol, iph_length

def unpack_eth(eth_header):
	''' Interpret the bytes as an Eth header '''
	# unpack the ethernet packet
	ether = struct.unpack('!6s6s2s', eth_header)
	# extract the destination mac
	dest_mac = format_mac(ether[0].hex())
	# extract the src mac address
	src_mac = format_mac(ether[1].hex())
	# extract the type of ethernet frame
	eth_type = ether[2].hex()
	return src_mac, dest_mac, eth_type

def unpack_tcp(tcp_packet):
	''' Interpret the bytes as a TCP packet '''
	tcp = struct.unpack('!HHLLBBHHH', tcp_packet)
	src_port = tcp[0]
	dest_port = tcp[1]
	#print(f'Src: {src_port}\nDest: {dest_port}')
	data = ''
	return src_port, dest_port

def unpack_udp(udp_packet):
	''' Interpret the bytes as a UDP packet '''
	udp = struct.unpack('!HHHH', udp_packet)
	src_port = udp[0]
	dest_port = udp[1]
	data = ''
	return src_port, dest_port

def format_mac(mac):
	''' Format the MAC address with hyphens '''
	# insert hyphens
	return ''.join([f'{mac[i:i+2]}:' if i < 10 else f'{mac[i:i+2]}' for i in range(0, len(mac), 2)])

def serialize_packet_info(src_mac, dest_mac, eth_type, packet_data, idx):
	if eth_type == "0800":
		# extract IP info
		version, src_ip, dest_ip, protocol, iph_length = unpack_ip(packet_data[14:34])
		# IPv4
		if protocol == 1:
			# ICMP packet
			return f'{YELLOW}{idx : >6}{END} {time.strftime("%I:%M:%S%p") : >11} {BLUE}{src_ip : <21}{END}[{CYAN}{src_mac}{END}] ICMP {YELLOW}\u27f9   {RED}{dest_ip : <21}{END}[{CYAN}{dest_mac}{END}]'
		elif protocol == 6:
			# TCP packet
			src_port, dest_port = unpack_tcp(packet_data[34:54])
			src = f'{src_ip}:{END}{src_port}'
			dest = f'{dest_ip}:{END}{dest_port}'
			if (packet_data):
				print(packet_data)
			if src_port == 443 or dest_port == 443:
				return f'{YELLOW}{idx : >6}{END} {time.strftime("%I:%M:%S%p") : >11} {BLUE}{src : <25}[{CYAN}{src_mac}{END}] TLS  {YELLOW}\u27f9   {RED}{dest : <25}[{CYAN}{dest_mac}{END}]'
			return f'{YELLOW}{idx : >6}{END} {time.strftime("%I:%M:%S%p") : >11} {BLUE}{src : <25}[{CYAN}{src_mac}{END}] TCP  {YELLOW}\u27f9   {RED}{dest : <25}[{CYAN}{dest_mac}{END}]'
		elif protocol == 17:
			# UDP packet
			src_port, dest_port = unpack_udp(packet_data[34:42])
			src = f'{src_ip}:{END}{src_port}'
			dest = f'{dest_ip}:{END}{dest_port}'
			proto = 'UDP'
			if src_port == 53 or dest_port == 53:
				return f'{YELLOW}{idx : >6}{END} {time.strftime("%I:%M:%S%p") : >11} {BLUE}{src : <25}[{CYAN}{src_mac}{END}] DNS  {YELLOW}\u27f9   {RED}{dest : <25}[{CYAN}{dest_mac}{END}]'
			return f'{YELLOW}{idx : >6}{END} {time.strftime("%I:%M:%S%p") : >11} {BLUE}{src : <25}[{CYAN}{src_mac}{END}] UDP  {YELLOW}\u27f9   {RED}{dest : <25}[{CYAN}{dest_mac}{END}]'
	
	elif eth_type == "86DD":
		# IPv6 packet detected
		pass
	elif eth_type == "0806":
		# ARP packet
		src = f'{END}[{CYAN}{src_mac}{END}]'
		dest = f'{END}[{CYAN}{dest_mac}{END}]'
		return f'{YELLOW}{idx : >6}{END} {time.strftime("%I:%M:%S%p") : >11} {src : >53} ARP  {YELLOW}\u27f9  {dest : >54}'
	# drop packets that aren't ICMP/TCP/UDP
	
def display_packet_info(src_mac, dest_mac, eth_type, packet_data, idx):
	''' Print the packet info to the console '''
	info = serialize_packet_info(src_mac, dest_mac, eth_type, packet_data, idx)
	if (info):
		print(info)

def host_lookup(addr):
	try:
		# try to retrieve the host name
		host = socket.gethostbyaddr(addr)
		return host[0]
	except:
		return addr

async def read_socket(idx, interface):
	''' Read a packet from the socket '''	
	# receive tuple of data and ...
	packet = sock.recvfrom(65536)
	# grab network data
	packet_data, addr = packet
	# extract MAC info
	src_mac, dest_mac, eth_type = unpack_eth(packet_data[0:14])
	# display packet
	display_packet_info(src_mac, dest_mac, eth_type, packet_data, idx)

async def listen(interface):
	idx = 1
	while True:
		await read_socket(idx, interface)
		idx += 1

if __name__ == "__main__":
	# FIXME: check for a linux system
	# get available interfaces
	ifaces = os.listdir('/sys/class/net/')
	if len(sys.argv) < 2:
		print('Not enough arguments. Please call `protophile <interface>`')
		sys.exit(1)
	interface = sys.argv[1]
	if interface not in ifaces:
		print(f"Interface {interface} not found.")
		exit(1)
	# read all packets captured
	sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	# bind socket to the wireless interface
	sock.bind((interface, 0x0003))
	#sock.bind(('wlp2s0', 0x0003))
	#sock.bind(('enp0s31f6', 0x0003))
	# Print ProtoPhile header
	print_header()
	# Print packet capture start time
	print(f'Starting packet capture at {time.strftime("%I:%M:%S %p on %b %d %Y")}\n')
	# Run packet capture until program is killed
	asyncio.run(listen(interface))
