#!/usr/bin/env python3
#
# Python Trivial Port Scanner Cycle 7
# Runs a SYN scan, traceroute, or both on the IP target/domain name and port
# range you specify.

# This file has been formatted with "black" from https://github.com/python/black
import argparse
import socket
import random
from scapy.all import *


class ScanTarget:

    # Builds a ScanTarget from target and ports
    def __init__(self, targetSpec=None, targ=None, portList=None):

        self.target = None
        self.ports = []

        if targetSpec is not None:
            # The first token is the target of the scan (IP or domain name).
            self.target = targetSpec[0]

            # Subsequent tokens are ports to scan at the target
            for port in range(1, len(targetSpec)):
                self.ports.append(int(targetSpec[port]))
        else:
            self.target = targ
            tokens = portList.split()
            for port in tokens:
                self.ports.append(int(port))


class SynScan:
    # Build the list of ports to be scanned.
    def buildPortList(startPort, endPort, randomScan):
        portList = []

        # Changed this to use range()
        for port in range(startPort, endPort):
            portList.append(port)

        # if the user wants to randomize the port scan order, we
        # take the list of ports to be scanned, and reandomly
        # swap elements to "scramble" the list.
        if randomScan is not None:

            # Get the number of ports in the list to be scanned.
            numPorts = len(portList)

            # For each port in the list, swap it with another port
            # at a random list position.
            for index in range(numPorts):
                newPosition = random.randint(0, numPorts - 1)
                swapvalue = portList[index]
                portList[index] = portList[newPosition]
                portList[newPosition] = swapvalue

            # Print the scan order.
            print("Ports will be scanned in this order: ")
            print(portList)

        return portList

    # Creats a SynScan object according to the command-line options.
    def __init__(self, clargs=None, tgt=None, clports=None):
        # Initialize the set of targets and their associated ports
        self.targets = []

        if clargs is not None:
            # If the user specified a target file, process it.
            if args.filename is not None:
                try:

                    # Open the file
                    print("Reading {0}\n".format(args.filename))
                    lines = open(args.filename, "r")

                    # While not EOF do
                    for line in lines:

                        # Split the scan spec into tokens
                        tokens = line.split()

                        # If the first character of the first token is not '#' then
                        # process the line. Otherwise, the line is a comment, and
                        # should be ignored.
                        if not tokens[0].startswith("#"):
                            scanTarget = ScanTarget(targetSpec=tokens)
                            self.targets.append(scanTarget)

                    # Close the file
                    lines.close()
                except:
                    print("Error opening or closing " + args.filename)
                    exit()
            else:
                # Target and port range are specified on command line.
                ports = buildPortList(args.first_port, args.last_port, args.random)
                scanTarget = ScanTarget(targ=args.target, portList=ports)
                self.targets.append(scanTarget)
        else:
            # Target list not from command line args.
            scanTarget = ScanTarget(targ=tgt, portList=clports)
            self.targets.append(scanTarget)

        # At this point, the SynScan object contains a list of
        # ScanTarget objects. Each ScanTarget object contains
        # a scan target, and a list of one or more ports to scan.

    # This method runs SYN scans on the target IP addresses or domain names
    # specified by the user.
    def synscan(self):
        for scanTarget in self.targets:
            # Initialize the TCP header
            tcpPkt = TCP(sport=RandShort(), flags="S")

            # Assign a set of ports or just one port to the TCP header.
            # These are the ports that will be scanned.
            tcpPkt.dport = []
            tcpPkt.dport = scanTarget.ports

            ans = []
            unans = []

            # If the user specified an interface to communicate over, use it.
            # Otherwise, use the default.
            if args.interface is not None:
                # Get the name of our ethernet interface and send SYN
                ans, unans = sr(
                    IP(dst=scanTarget.target) / tcpPkt,
                    iface=args.interface,
                    verbose=0,
                    timeout=12,
                )
            else:
                # Send SYN on default interface
                ans, unans = sr(
                    IP(dst=scanTarget.target) / tcpPkt, verbose=0, timeout=12
                )

            # Report open ports
            print("These ports are open on {0}".format(scanTarget.target))
            print("-----------------------------------------------")
            for result in ans:
                reply = result[1]
                if reply[TCP].flags == "SA":
                    print(
                        "({0}) ".format(reply[TCP].sport)
                        + reply.sprintf("%TCP.sport% is open")
                    )
            print("-----------------------------------------------\n\n")


###############################################################################
# Start of main program methods.
###############################################################################
# Parse the command-line arguments
def parseArgs():
    # Create an arg parser
    parser = argparse.ArgumentParser()

    # Add the command-line arguments to the parser.
    # Get the operating mode. Either "syn" for SYN scan, "troute" for
    # traceroute, or "rscan" for SYN scan of traceroute results.
    parser.add_argument(
        "mode",
        help="(syn|troute|rscan|ping) = SYN scan, "
        + "traceroute, "
        + "SYN scan of traceroute results, "
        + "ping - find all active hosts on local LAN.",
        choices=["syn", "troute", "rscan", "ping"],
    )

    # Target IP or domain name to scan
    parser.add_argument(
        "target",
        help="IPv4 address/domain for scan/traceroute/rscan modes."
        + 'Note for SYN scans: set target to "file" when using the '
        + "-k or --filename options. For ping mode, this is the first"
        + "three octets of the /24 subnet to ping. "
        + "e.g. use 192.168.1 to ping the subnet 192.168.1/24 ",
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

    # Ethernet interface to use. Useful for machines with multiple
    # network interfaces.
    parser.add_argument(
        "-i",
        "--interface",
        help="ethernet interface to communicate on, e.g. Ethernet, ens33",
    )

    # Filename containing scan targets and ports to perform a SYN scan on.
    parser.add_argument(
        "-n",
        "--filename",
        help="(syn mode only) Name of file containing SYN scan targets and " + "ports.",
    )

    # String of ports to scan (rscan mode only)
    parser.add_argument(
        "-p",
        "--rscan-ports",
        help="(rscan mode only) ports to be scan for each host in "
        + 'traceroute route, e.g. "25 80 443 464". List must be '
        + "enclosed in quotation marks.",
    )

    # Whether or not to randomize the order of the SYN scan.
    # The nargs='?' will assume the value specified by const= if
    # the user does not specify a value (which they should not,
    # because this parameter does not take any values).
    parser.add_argument(
        "-r",
        "--random",
        help="(syn mode only) Randomize the order of the syn scan",
        nargs="?",
        const=None,
    )

    # Type of packet to send for ping (ping mode only)
    parser.add_argument(
        "-k",
        "--packet-type",
        help="(ping mode only) (icmp|udp) = ICMP ping, UDP ping",
        choices=["icmp", "udp"],
        default="icmp",
    )

    # Parse the commmand line arguments, and return them in an object.
    args = parser.parse_args()
    return args


# This method runs a traceroute on the target IP address or domain name
# specified by the user.
def runTraceroute(args):

    # Scapy provides a traceroute function, we leverage it here. Verbose
    # output is disabled.
    ans = []
    unans = []
    if args.interface is not None:
        ans, unans = traceroute(
            args.target, dport=args.tport, iface=args.interface, verbose=0
        )
    else:
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
    for host in route:
        print("Host: " + host)
        synScan = SynScan(tgt=host, clports=args.rscan_ports)
        synScan.synscan()
        print("============================================================\n")


# This method finds devices on the local LAN by sending an ICMP or UDP ping
# to each host in a /24 subnet.
def ping(args):

    pingPacket = None

    # Build the subnet
    tokens = []
    tokens = args.target.split(".")

    subnet = tokens[0] + "." + tokens[1] + "." + tokens[2]

    print(
        "Running {0} ping on the subnet {1}".format(
            args.packet_type.upper(), subnet + "/24"
        )
    )

    # What type of ping does the user want?
    if args.packet_type == "icmp":
        pingPacket = ICMP()
    else:
        # Port 0 is used because it should be closed. If the host is
        # alive, it should return a "host unreachable" error, which
        # leaks the fact that the host is up.
        pingPacket = UDP(dport=0)

    # Check hosts 1-253. If they respond to the ping, they are marked
    # as being "live".
    for host in range(1, 254):
        target = subnet + "." + str(host)
        response = None

        # We use sr1() here, as it only returns the packet that
        # answered our ping (or nothing).
        if args.interface is not None:
            response = sr1(IP(dst=target) / pingPacket, iface=args.interface, timeout=2)
        else:
            response = sr1(IP(dst=target) / pingPacket, verbose=0, timeout=2)
        if response is not None:
            print(response.sprintf("%IP.src% is up"))


############################################################################
# Start of main program
############################################################################

# Get command-line args
args = parseArgs()

# Process commands until user tells us to quit
if args.mode == "syn":
    synScan = SynScan(clargs=args)
    synScan.synscan()
elif args.mode == "troute":
    route = runTraceroute(args)
elif args.mode == "ping":
    ping(args)
elif args.mode == "rscan":
    if args.rscan_ports is not None:
        routeScan(args)
    else:
        print("Must specify --rscan-ports when using rscan mode.")
print("")
