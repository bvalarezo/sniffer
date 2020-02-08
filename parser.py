#! /usr/bin/env python

from scapy.all import *

def parse(interface, tracefile, expression):
    retval = 0
    if tracefile:
        retval = parse_file(tracefile, expression)
    elif interface:
        retval = parse_interface(interface, expression)
    else:
        retval = 1
    return retval

def parse_file(tracefile, expression):
    retval = 0
    #open file
    #prase with scapy
    #for line in file
    #print desired packets
    return retval

def parse_interface(interface, expression):
    retval = 0
    #select int
    #parse with scapy
    #for line in file
    #print desired packets
    return retval

def decode_HTTP(packet):
    #takes in packet
    #parse if GET or POST
    #print destination name
    #date timestamp HTTP SRC_IP:PORT -> DST_IP:PORT domain_name HTTP_METHOD location
    #2020-02-04 13:14:33.224487 HTTP 192.168.190.128:57234 -> 23.185.0.4:80 www.cs.stonybrook.edu GET /research/NationalSecurityInstitute
    #return string

def decode_TLS(packet):
    #takes in packet
    #parse Client Hello
    #print TLS version
    #print destination
    #date timestamp TLS version SRC_IP:PORT -> DST_IP:PORT domain_name
    #2020-02-04 13:14:24.494045 TLS v1.3 192.168.190.128:59330 -> 104.244.42.193:443 twitter.com
    #return string

def identify_pkt(packet):
    #takes in packet
    #if HTTP, return HTTP
    #elif HTTPS, return TLS
    #else, return OTHER


