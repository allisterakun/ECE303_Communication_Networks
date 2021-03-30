import sys
import socket

# https://www.netresec.com/?page=Blog&month=2011-11&post=Passive-OS-Fingerprinting
OS = {
    (64, 5840): "Linux (kernel 2.4 and 2.6)",
    (64, 5720): "Google's customized Linux",
    (64, 65535): "FreeBSD",
    (128, 65535): "Windows XP",
    (128, 8192): "Windows 7, Vista and Server 2008",
    (255, 4128): "Cisco Router (iOS 12.4)"
}

# If there isn't a range defined, the program
# will scan ports from 1-1024 by default.
if len(sys.argv) == 2:
    hostname = sys.argv[1]
    startPort = 1
    endPort = 1024

# Parse the input if a port range is specified
elif len(sys.argv) == 4:
    if sys.argv[2] == "-p":
        hostname = sys.argv[1]
        portRange = sys.argv[3].split(":")
        startPort = int(portRange[0])
        endPort = int(portRange[1]) + 1
    
    # Invalid input arguments
    else:
        sys.exit("ERROR: Invalid input.\nCorrect usage: python proj1.py hostname [-p m:n]")

# Invalid input arguments
else:
    sys.exit("ERROR: Invalid input.\nCorrect usage: python proj1.py hostname [-p m:n]")


host = socket.gethostbyname(hostname)

# Scan thru each port in the port range
for portNumber in range(startPort, endPort):
    # Thanks to Mark Koszykowski for helping me with error handling
    try:
        s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        connection = s.connect_ex((host,portNumber))

        if connection == 0:
            try:
                print(F"Port {portNumber} is open for {socket.getservbyport(portNumber)} service", end=""),
            except:
                print(F"Port " + str(portNumber) + "is open", end=""),

            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            winSize = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) - 1

            try:
                print(F" with OS type: {OS.get((ttl, winSize))}.")
            except:
                print(F" with unknown OS type.")

    except socket.gaierror:
        sys.exit("Cannot resolve hostname")
    except socket.error:
        sys.exit("No response from server")

s.close()