# CSC842
CSC 842 projects

TPS3.py is the version for Cycle 3. It supersedes the initial version, tps.py.

TPS5.py is the version for Cycle 5. It supersedes TPS3.py.
New in this version:
  - The user now has the option to randomize the order that ports are scanned on the target machine. This is to help prevent the scan being detected by the target.
  - There is a new mode "rscan" which performs a traceroute to the target, and then executes a SYN scan against each host in the resulting route.
  - Open ports identified by the SYN scan now include the protocol as well as the port number (e.g "80 http")

TPS7.py is the version for Cycle 5. It supersedes TPS5.py.
New in this version:
  - The user now has the option to specify scan targets and ports in a data file. 
  - The user may now specify which ports to scan on hosts found by traceroute (rscan mode).
  - The user now has the capability to perform an ICMP or UDP ping against all hosts in a /24 subnet. For example, 192.168.1/24.

Geolocator
geoloctor.py is the project for Cycle 9.
  - Geolocation of cellular emitter by using three cell towers (triangualtion).
  - Uses either RSS values or signal propegation time for distance estimates in triangulation process.
  - Source: geolocator.py
  - Sample input data file: datafile.txt
  
