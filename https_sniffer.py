#!/usr/bin/env python3

from sys import argv
from scapy.all import sniff, Ether, DHCP, IP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, time

packets, verbose, store, write = [], True, False, False

status_color = {
	'+': Fore.GREEN,
	'-': Fore.RED,
	'*': Fore.YELLOW,
	':': Fore.CYAN,
	' ': Fore.WHITE,
}

packets = 0

def get_time():
	return strftime("%H:%M:%S", localtime())
def display(status, data):
	print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments(*args):
	parser = OptionParser()
	for arg in args:
		parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
	return parser.parse_args()[0]

def sniff_packets(iface=None):
	if iface:
		sniff(rn=process_packet, iface=iface, store=False)
	else:
		sniff(prn=process_packet, store=False)
def process_packet(packet):
	if packet.haslayer(HTTPRequest):
		url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
		ip = packet[IP].src
		method = packet[HTTPRequest].Method.decode()
		display('+', f"{ip} : {Back.MAGENTA}{method}{Back.RESET} => {url}")
		if packet.haslayer(Raw):
			display('*', f"RAW Data : {packet.Raw.load}")

if __name__ == "__main__":
	if len(argv) == 2:
		sniff_packets(argv[1])
	else:
		sniff_packets()