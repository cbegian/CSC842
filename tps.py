#!/usr/bin/env python3
#
#Python Trivial Port Scanner
#Runs a SYN scan on the IP target and port range you specify.
import socket
import random
from sys import platform
from scapy.all import *

NOT_CHOSEN = -1

#Get our Ethernet I/F, based upon the OS. Currently supports Linux and Windows
def getInterface():
	if platform == 'Linux':
		wan_if = 'ens33'
	else:
		#Windows assumed
		wan_if = 'Ethernet'
	return ( wan_if )

#Get the target port range		
def getPortRange():

	#initialize port range to scan
	startPort = NOT_CHOSEN
	endPort = NOT_CHOSEN
	
	#The user can scan a range of ports, or just a single port (i.e. a range
	#of length 1).
	print( "This tool will scan a single port, or a range of ports at the IP" )
	print( "you have chosen. " )
	singlePortFlag = input( "Do you want to scan a single port? (Y/N) ")
	if singlePortFlag == 'Y' or singlePortFlag == 'y':
		startPort = input( "Enter the port number. (Example: 21): " )
		#For a single port, the first and last ports of the range are equal.
		endPort = startPort
	else:
		print( "Enter the first port number in the range." )
		startPort = input( "(Example: 21): " )
		print( "Enter the last port number in the range." )
		endPort = input( "(Example: 48000): " )
	return ( startPort, endPort )
	
def runSYNScan():
	#Get the target IP for the scan
	print( "Enter a single target IPv4 address in dotted decimal notation." )
	targetIP = input( "(Example: 123.4.56.178): " )
	
	#Get the first and last port numbers in the range to scan
	startPort, endPort = getPortRange()
	
	#get the name of our ethernet interface
	wan_if = getInterface()

	#Run the SYN scan
	ans, unans = sr( IP( dst=str(targetIP) )/TCP( sport=RandShort(), 
												dport=(int(startPort), int(endPort) ), 
												flags="S" ),
												iface="Ethernet", timeout=30 )
	
	#Report open ports
	print( "The following ports are open" )
	print( "----------------------------" )
	for result in ans:
		if result[1][TCP].flags == "SA":
			print( result[1][TCP].sport, "is open" )

#Process commands until user tells us to quit
done = False
while not done:
	command = input( "What do you want to do? 1 = Run SYN Scan, 2 = Quit: " )
	if command == '1':
		runSYNScan()
	elif command == '2':
		done = True
	print( "" )
