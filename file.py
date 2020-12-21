#! /usr/bin/env python

from scapy.all import *
import argparse


#example to see if it works, worked with me (verified with wireshark)
#ip_layer = IP(dst="192.168.1.1")
#icmp_layer = ICMP(seq=9999)
#packet = ip_layer / icmp_layer
#send(packet)

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--ip", help = "Destination IP Address")
parser.add_argument("-p", "--protocol", help = "Protocol name")
parser.add_argument("-n", "--number", help = "Number of packets")


# Read arguments from command line
args = parser.parse_args()
 
print (args)
if args.ip:
	print("Diplaying IP as: % s" % args.ip)
	ip_layer = IP(dst=args.ip)

	#layer = ICMP()
	#packet = ip_layer / layer

	# loop=1 send packets until CTRL-C is pressed
	#send(packet, loop=1)

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
	print("No args")


