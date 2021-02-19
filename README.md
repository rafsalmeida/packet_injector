# packet_injector

packet_injector is an application to craft network packets for subsequent injection into the network for educational purposes.

## Installation guide

Requirements:
* [Python](https://www.python.org/downloads/)
* [Scapy](https://scapy.net/download/)

## Running
1. Clone this repository and navigate to the main directory
2. To execute a SYN Flood attack execute the following command:
```
python file.py -i <Destination address> | -f <Text file with multiple addresses> --syn <Payload> [-s <Source address>]
```
3. To execute an ARP spoofing attack execute the following command:
```
python file.py -i <Destination address> | -f <Text file with multiple addresses> --arp <Host address> 
```
4. To execute a Ping Flood attack execute the following command:
```
python file.py -i <Destination address> | -f <Text file with multiple addresses> --icmp <Payload> [-s <Source address>] [-n <Number of packets>]
```
