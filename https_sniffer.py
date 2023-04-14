#!/usr/bin/env python3

from os import geteuid
from pickle import load, dump
from scapy.all import sniff, IP, Raw
from scapy.layers.http import HTTPRequest
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime

packets_global, verbose = [], True

status_color = {
	'+': Fore.GREEN,
	'-': Fore.RED,
	'*': Fore.YELLOW,
	':': Fore.CYAN,
	' ': Fore.WHITE,
}

def get_time():
	return strftime("%H:%M:%S", localtime())
def display(status, data):
	print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments(*args):
	parser = OptionParser()
	for arg in args:
		parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
	return parser.parse_args()[0]

def check_root():
	return geteuid() == 0

def sniff_packets(iface=None):
	if iface:
		sniff(rn=process_packet, iface=iface, store=False)
	else:
		sniff(prn=process_packet, store=False)
def process_packet(packet):
	if packet.haslayer(HTTPRequest):
		packets_global.append(packet)
		if not verbose:
			print(f"\rPackets Sniffed = {len(packets_global)}", end='')
		url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
		ip = packet[IP].src
		method = packet[HTTPRequest].Method.decode()
		if verbose:
			display('+', f"{ip} : {Back.MAGENTA}{method}{Back.RESET} => {url}")
		if packet.haslayer(Raw):
			if verbose:
				display('*', f"RAW Data : {packet.Raw.load}")

if __name__ == "__main__":
	data = get_arguments(('-i', "--iface", "iface", "Interface on which sniffing has to be done"),
					     ('-v', "--verbose", "verbose", "Display Useful Information related to the packets on the screen (True/False)(Default = True)"),
						 ('-w', "--write", "write", "Dump the Packets to file"),
						 ('-r', "--read", "read", "Read Packets from a dump file"))
	if data.read:
		try:
			with open(data.read, 'rb') as file:
				packets = load(file)
		except FileNotFoundError:
			display('-', f"{Back.MAGENTA}{data.read}{Back.RESET} File not found!")
			exit(0)
		except:
			display('-', f"Error reading from file {Back.MAGENTA}{data.read}{Back.RESET}")
			exit(0)
		for packet in packets:
			process_packet(packet)
		exit(0)
	if data.verbose == "False":
		verbose = False
	if not check_root():
		display('-', f"This Program requires {Back.MAGENTA}root{Back.RESET} Privileges")
		exit(0)
	sniff_packets(data.iface)
	print()
	display(':', f"Total Packets Sniffed = {Back.MAGENTA}{len(packets_global)}{Back.RESET}")
	if data.write:
		with open(data.write, 'wb') as file:
			dump(packets_global, file)