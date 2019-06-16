# CSC842
CSC 842 projects

TPS3.py is the version for Cycle 3. It supersedes the initial version, tps.py.

TPS5.py is the version for Cycle 5. It supersedes TPS3.py.
New in this version:
  - The user now has the option to randomize the order that ports are scanned on the target machine. This is to help prevent the scan being detected by the target.
  - There is a new mode "rscan" which performs a traceroute to the target, and then executes a SYN scan against each host in the resulting route.
  - Open ports identified by the SYN scan now include the protocol as well as the port number (e.g "80 http")
