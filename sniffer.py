#! /usr/bin/env python

import sys, getopt
from scapy.all import *

#PREDEFINED 
OPTIONS = "i:r:h"
TRACEFILE = ""
INTERFACE = ""
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
            print("Sniffer: A websniffer used to parse HTTP and HTTPS traffic")
            usage(argv[0], 0)
        else:
            usage(argv[0])
    if not bool(INTERFACE) ^ bool(TRACEFILE):
        print("Sniffer: Unable to sniff from both tracefile and live packets")
        usage(argv[0])
    if INTERFACE:
        INTERFACE = "default"
    EXPRESSION = args
    if TRACEFILE:
        pass
        #read from file
    else:
        pass
        #read from stream
    print(INTERFACE + ", " + TRACEFILE)
    sys.exit(0)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

