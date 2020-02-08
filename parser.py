#! /usr/bin/env python

from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello
import cryptography

def parse(iface=None, pcap=None, expression=None):
    load_layer('http')
    load_layer('tls')
    if pcap:
        retval = parse_file(pcap, expression)
    elif iface or not pcap:
        retval = parse_interface(iface, expression)
    else:
        retval = 1
    return retval

def parse_file(pcap, expression):
    retval = 0
    print("Reading packets from pcap...")
    sniff(offline=pcap, filter=expression, prn=identify_pkt)
    return retval

def parse_interface(iface, expression):
    retval = 0
    print("Reading packets from interface...")
    if iface:
        sniff(filter=expression, prn=identify_pkt, iface=iface)
    else:
        sniff(filter=expression, prn=identify_pkt)
    #capture ctrl-c ?
    return retval

def decode_HTTP(packet):
    retval = 0
    print(packet[HTTPRequest])
    return retval
    #takes in packet
    #parse if GET or POST
    #print destination name
    #date timestamp HTTP SRC_IP:PORT -> DST_IP:PORT domain_name HTTP_METHOD location
    #2020-02-04 13:14:33.224487 HTTP 192.168.190.128:57234 -> 23.185.0.4:80 www.cs.stonybrook.edu GET /research/NationalSecurityInstitute
    #return string

def decode_TLS(packet):
    retval = 0
    print("tls found")
    print(packet)
    return retval
    #takes in packet
    #parse Client Hello
    #print TLS version
    #print destination
    #date timestamp TLS version SRC_IP:PORT -> DST_IP:PORT domain_name
    #2020-02-04 13:14:24.494045 TLS v1.3 192.168.190.128:59330 -> 104.244.42.193:443 twitter.com
    #return string

def identify_pkt(packet):
    if packet.haslayer(HTTPRequest):
        decode_HTTP(packet)
    elif packet.haslayer(TLSClientHello): #help here
        decode_TLS(packet)
    else:
        pass

