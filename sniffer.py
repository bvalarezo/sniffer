#! /usr/bin/env python3

import sys, getopt
from parser import parse
#PREDEFINED 
OPTIONS = "i:r:h"
TRACEFILE = None
INTERFACE = None
EXPRESSION = ""
#

def usage(name, status=2):
    print("Usage: %s [-i interface] [-r tracefile] expression" % name)
    sys.exit(status)

def main(argc, argv):
    global TRACEFILE, INTERFACE, EXPRESSION
    try:
        opts, args = getopt.getopt(argv[1:], OPTIONS)
    except getopt.GetoptError as e:
        print(e)
        usage(argv[0])
    for opt, optarg in opts:
        if opt == "-i":
            INTERFACE = optarg
        elif opt == "-r":
            TRACEFILE = optarg
        elif opt == "-h":
            print("Sniffer: A websniffer used to parse HTTP and TLS traffic")
            usage(argv[0], 0)
        else:
            usage(argv[0])
    EXPRESSION = " ".join(map(str, args))
    try:
        retval = parse(iface=INTERFACE, pcap=TRACEFILE, expression=EXPRESSION)
    except PermissionError as e:
        print(e)
        print("Sniffer: Please run %s with root permissions" % argv[0])
        retval = 1
    sys.exit(retval)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

