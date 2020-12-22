#! /usr/bin/env python

from scapy.all import *
import argparse

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--ip", help = "Destination IP Address")
parser.add_argument("-s", "--source", help = "Source IP Address")
parser.add_argument("-p", "--protocol", help = "Protocol name")
parser.add_argument("-n", "--number", help = "Number of packets")


# Read arguments from command line
args = parser.parse_args()
 
print (args)
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
	print("Defining one/multiple destination IP Addresses is mandatory.")


