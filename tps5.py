#!/usr/bin/env python3
#
# Python Trivial Port Scanner
# Runs a SYN scan, traceroute, or both on the IP target /domain name and port
# range you specify.
import argparse
import socket
import random
from scapy.all import *


# Parse the command-line arguments
def parseArgs():
    # Create an arg parser
    parser = argparse.ArgumentParser()

    # Add the command-line arguments to the parser
    # Get the operating mode. Either "syn" for SYN scan, "troute" for traceroute, "mac" to get the MAC address,
    # or "rscan" for SYN scan of traceroute results.
    parser.add_argument(
        "mode",
        help="(syn|troute|rscan) = SYN scan, "
        + "traceroute, "
        + "SYN scan of traceroute results",
        choices=["syn", "troute", "mac", "rscan"],
    )

    # Target IP or domain name to scan
    parser.add_argument(
        "target",
        help="IPv4 address/domain for scan/traceroute/rscan, or IPv4 address for mac",
    )

    # Optional arguments:
    # Destination port for traceroute.
    parser.add_argument(
        "-t",
        "--tport",
        help="(troute mode only) port to traceroute to (default 80)",
        type=int,
        default=80,
    )

    # First port number to scan in a SYN scan
    parser.add_argument(
        "-f",
        "--first-port",
        help="(syn mode only) First port to include in scan (default 20)",
        type=int,
        default=20,
    )

    # Last port number to scan in a SYN scan
    parser.add_argument(
        "-l",
        "--last-port",
        help="(syn mode only) Last port to include in scan (default 1024)",
        type=int,
        default=1024,
    )

    # Whether or not to randomize the order of the SYN scan
    parser.add_argument(
        "-r",
        "--random",
        help="(y|n) If y, randomize the order of the syn scan (default n)",
        default="n",
        choices=["y", "n"],
    )

    # Ethernet interface to use. Useful for machines with multiple network interfaces.
    parser.add_argument(
        "-i",
        "--interface",
        help="ethernet interface to communicate on, e.g. Ethernet, ens33",
    )

    # Parse the commmand line arguments, and return them in an object.
    args = parser.parse_args()
    return args


# Build the list of ports to be scanned.
def buildPortList(startPort, endPort, randomScan):
    portList = []
    port = startPort
    while port <= endPort:
        portList.append(port)
        port += 1

    # if the user wants to randomize the port scan order, we
    # take the list of ports to be scanned, and reandomly
    # swap elements to "scramble" the list.
    if randomScan == "y":
        # List index starts at the beginning of the list
        index = 0

        # Get the number of ports in the list to be scanned.
        numPorts = len(portList)

        # For each port in the list, swap it with another port
        # at a random list position.
        while index < numPorts:
            newPosition = random.randint(0, numPorts - 1)
            swapvalue = portList[index]
            portList[index] = portList[newPosition]
            portList[newPosition] = swapvalue
            index += 1

        # Print the scan order.
        print("Ports will be scanned in this order: ")
        print(portList)

    return portList


# This method runs a SYN on the target IP address or domain name
# specified by the user. The user may also specify a range of ports
# to be scanned.
def runSYNScan(args):
    # Get the target for the scan. This will be an IPv4 address, or a domain
    # name. However, Scapy can use a domain name instead of an IP, without
    # having to write special code.
    target = args.target

    # Get the first and last port numbers in the range to scan. If only a single
    # port is being scanned, these will be the same.
    startPort = args.first_port
    endPort = args.last_port

    # Initialize the TCP header
    tcpPkt = TCP(sport=RandShort(), flags="S")

    # Assign a range of ports or just one port to the TCP header. These are the ports
    # that will be scanned.
    if startPort != endPort:
        tcpPkt.dport = buildPortList(startPort, endPort, args.random)
    else:
        tcpPkt.dport = startPort

    ans = []
    unans = []

    # If the user specified an interface to communicate over, use it. Otherwise,
    # use the default.
    if args.interface != None:
        # get the name of our ethernet interface
        ans, unans = sr(IP(dst=str(target)) / tcpPkt, iface=args.interface, timeout=12)
    else:
        ans, unans = sr(IP(dst=str(target)) / tcpPkt, timeout=12)

    # Report open ports
    print(
        "The following ports between {0} and {1} are open on {2}".format(
            startPort, endPort, target
        )
    )
    print("-----------------------------------------------")
    for result in ans:
        reply = result[1]
        if reply[TCP].flags == "SA":
            print(
                "({0}) ".format(reply[TCP].sport) + reply.sprintf("%TCP.sport% is open")
            )


# This method runs a traceroute on the target IP address or domain name
# specified by the user.
def runTraceroute(args):

    # Scapy provides a traceroute function, we leverage it here. Verbose output
    # is disabled.
    ans, unans = traceroute(args.target, dport=args.tport, verbose=0)

    # Initially, the route to the target host is empty
    route = []

    # Get the number of hops to the target host
    replies = len(ans)

    print("Traceroute results:")
    print("-------------------")
    if replies > 0:

        # Flag to indicate when we have reached the target host
        routeComplete = False

        # Iterate over the replies. For each hop, add that host to the route.
        # Stop when we reach the target host (last host in our route) or when
        # we run out of hops to process.
        while replies > 0 and routeComplete == False:
            # Get the host at this hop
            reply = ans.pop(0)
            replies -= 1

            # Add the host at this hop to the route
            route.append(reply[1].src)

            # Print the host at this hop
            print(reply[1].src)

            # Have we reached the target host?
            if isinstance(reply[1].payload, TCP):
                routeComplete = True
    else:
        # No route to host
        print("Host unreachable")

    print("-------------------\n\n")

    return route


# This method performs a traceroute to the target, and then performs a
# SYN scan on each host in the route.
def routeScan(args):

    print("============================================================\n")
    # Run the traceroute
    route = runTraceroute(args)

    # If there was a route to the target, run a SYN scan on each
    # host in the route.
    while len(route) > 0:
        args.target = route.pop(0)
        print("Host: " + args.target)
        runSYNScan(args)
        print("============================================================\n")


############################################################################
# Start of main program
############################################################################

# Get command-line args
args = parseArgs()

# Process commands until user tells us to quit
if args.mode == "syn":
    runSYNScan(args)
elif args.mode == "rscan":
    routeScan(args)
elif args.mode == "troute":
    route = runTraceroute(args)
print("")
