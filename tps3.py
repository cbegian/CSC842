#!/usr/bin/env python3
#
#Python Trivial Port Scanner
#Runs a SYN scan on the IP target and port range you specify.
import argparse
import socket
import random
from sys import platform
from scapy.all import *


#Parse the command-line arguments
def parseArgs():
	#Create an arg parser
	parser = argparse.ArgumentParser()
	
	#Add the command-line arguments to the parser
	#Target IP to scan
	parser.add_argument( "mode", help="syn = SYN scan, troute = traceroute" )
	parser.add_argument( "target", help="IPv4 address or domain to scan/traceroute" )

	parser.add_argument( "-tp", "--tport", help="(troute mode only) port to traceroute to (default 80)", type=int )
	parser.add_argument( "-first", "--first_port", help="(syn mode only) First port to include in scan (default 20)", type=int )
	parser.add_argument( "-last", "--last_port", help="(syn mode only) Last port to include in scan (default 1024)", type=int )
	parser.add_argument( "-if", "--interface", help="ethernet interface to communicate on, e.g. Ethernet, ens33" )
	args = parser.parse_args()
	return args

def runTraceroute( args ):

	#First, we need to get the IPv4 address (or domain) that we want to find a
	#route to.
	targetIP = args.target
	
	#if the user specified a port on the target machine, use it. Otherwise, use
	#the default (port 80).
	port = args.tport if args.tport != None else 80
		
	#Scapy provides a traceroute function, we leverage it here. Verbose output
	#is disabled (0).
	ans, unans = traceroute( targetIP, verbose=0 )
	
	#Initially, the route to the target host is empty
	route = []
	
	#Get the number of hops to the target host
	replies = len( ans )
	
	#Flag to indicate when we have reached the target host
	routeComplete = False;
	
	#Iterate over the replies. For each hop, add that host to the route.
	#Stop when we reach the target host (last host in our route) or when
	#we run out of hops to process.
	while replies > 0 and routeComplete == False:
		#Get the host at this hop
		reply = ans.pop( 0 )
		replies -= 1
		
		#Add the host at this hop to the route
		route.append( reply[1].src )
		
		#Have we reached the target host?
		if isinstance( reply[1].payload, TCP ):
			routeComplete = True
	
	return route


def runSYNScan( args ):
	#Get the target IP for the scan. This will be an IPv4 address, a domain
	#name. However, Scapy can use a domain name instead of an IP, without 
	#having to write special code.
	targetIP = args.target
	
	#Get the first and last port numbers in the range to scan. If only a single
	#port is being scanned, these will be the same.
	startPort = args.first_port if args.first_port != None else 20
	endPort = args.last_port if args.last_port != None else 1024

	#Initialize the TCP header
	tcpPkt = TCP( sport=RandShort(), flags="S" )
	
	#Assign a range of ports or just one port to the TCP header. These are the ports
	#that will be scanned.
	if startPort != endPort:
		tcpPkt.dport = ( startPort, endPort )
	else: 
		tcpPkt.dport = startPort
	
	ans =""
	unans = ""
	
	#If the user specified an interface to communicate over, use it. Otherwise,
	#use the default.
	if args.interface != None:
		#get the name of our ethernet interface
		ans, unans = sr( IP( dst=str(targetIP) )/ tcpPkt, iface=args.interface, 
															timeout=12 )
	else:
		ans, unans = sr( IP( dst=str(targetIP) )/ tcpPkt, timeout=12 )
	
	#Report open ports
	print( "The following ports are open" )
	print( "----------------------------" )
	for result in ans:
		if result[1][TCP].flags == "SA":
			print( result[1][TCP].sport, "is open" )

#Get command-line args
args = parseArgs()

#Process commands until user tells us to quit
if args.mode == 'syn':
	runSYNScan( args )
elif args.mode == 'troute':
	route = runTraceroute( args )
	if len( route ) > 0:
		for machine in route:
			print( machine )
	else:
		#No route to host
		print( "Host unreachable" )
else:
	print( "{0} is an invalid mode".format(args.mode) )
print( "" )
