#! /usr/bin/env python

from scapy.all import *
import argparse
import threading #thread module imported
import time #time module

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--ip", help = "Destination IP Address")
parser.add_argument("-s", "--source", help = "Source IP Address")
parser.add_argument("-p", "--protocol", help = "Protocol name")
parser.add_argument("-n", "--number", help = "Number of packets")
parser.add_argument("-f", "--file", type=argparse.FileType('r'), help = "File with destination IP Addresses")


# Read arguments from command line
args = parser.parse_args()
 
#threads 

def thread_delay(thread_name, delay, ip):
	time.sleep(delay)

	if args.source:
		print("Diplaying source as: % s" % args.source)
		ip_layer = IP(dst=ip, src=args.source)
	else:
		ip_layer = IP(dst=ip)

	if args.protocol:
		print("Diplaying protocol as: % s" % args.protocol)

		layer = eval(args.protocol.upper() + "()")

	else:
		layer = ICMP()

	packet = ip_layer / layer

	if args.number:
		send(packet, count=int(args.number))

	else:
		send(packet, loop=1)



if args.ip:
	print("Diplaying IP as: % s" % args.ip)

	if args.source:
		print("Diplaying source as: % s" % args.source)
		ip_layer = IP(dst=args.ip, src=args.source)
	else:
		ip_layer = IP(dst=args.ip)

	if args.protocol:
		print("Diplaying protocol as: % s" % args.protocol)

		layer = eval(args.protocol.upper() + "()")

	else:
		layer = ICMP()

	packet = ip_layer / layer

	if args.number:
		send(packet, count=int(args.number))

	else:
		send(packet, loop=1)

else:
	if args.file:
		Lines = args.file.readlines()

		#TODO transform the file to have an address in each line (Strip by space e.g)

		#TODO argument validation 

		count = 1;
		# Strips the newline character 
		for line in Lines: 
			
			print("Line:", line.strip())

			thread_n = threading.Thread(target=thread_delay, args=(count, 0, line.strip()))
			thread_n.start()
			count += 1
		
		#TODO work with the signal SIGINT
		
	
		
	else:
		print("Defining one/multiple destination IP Addresses is mandatory.")


