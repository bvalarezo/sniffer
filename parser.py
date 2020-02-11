#! /usr/bin/env python3

from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import ServerName
import cryptography

def parse(iface=None, pcap=None, expression=None):
    load_layer('http')
    load_layer('tls')
    retval = 0
    try:
        if pcap:
            parse_file(pcap, expression)
        elif iface or not pcap:
            parse_interface(iface, expression)
        else:
            retval = 1
    except BaseException as e:
        print(e)
        retval = 1
    return retval

def parse_file(pcap, expression):
    print("Reading packets from pcap...")
    sniff(offline=pcap, filter=expression, prn=identify_pkt)

def parse_interface(iface, expression):
    print("Reading packets from interface...")
    if iface:
        sniff(filter=expression, prn=identify_pkt, iface=iface)
    else:
        sniff(filter=expression, prn=identify_pkt)
    #capture ctrl-c ?

def decode_HTTP(pkt):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S.{}".format(repr(pkt.time).split('.')[1][:6]), time.localtime(pkt.time))
    src_ip = str(pkt[IP].src)
    sport = str(pkt[TCP].sport)
    dst_ip = str(pkt[IP].dst)
    dport = str(pkt[TCP].dport)
    host = str(pkt[HTTPRequest].Host.decode())
    method = str(pkt[HTTPRequest].Method.decode())
    path = str(pkt[HTTPRequest].Path.decode())
    return timestamp + " HTTP " + src_ip + ":" + sport + " -> " + dst_ip + ":" + dport + " " + host + " " + method + " " + path 

def decode_TLS(pkt):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S.{}".format(repr(pkt.time).split('.')[1][:6]), time.localtime(pkt.time))
    version = get_tls_version(pkt[TLSClientHello].version)
    src_ip = str(pkt[IP].src)
    sport = str(pkt[TCP].sport)
    dst_ip = str(pkt[IP].dst)
    dport = str(pkt[TCP].dport)
    server_name = str(pkt[ServerName].servername, "utf-8") #convert bytes to str
    return timestamp + " TLS " + version + " " + src_ip + ":" + sport + " -> " + dst_ip + ":" + dport + " " + server_name
    #2020-02-04 13:14:24.494045 TLS v1.3 192.168.190.128:59330 -> 104.244.42.193:443 twitter.com

def identify_pkt(packet):
    if packet.haslayer(HTTPRequest):
        print(decode_HTTP(packet))
    elif packet.haslayer(TLSClientHello) and packet.haslayer(ServerName): #help here
        print(decode_TLS(packet))
    else:
        pass

def get_tls_version(n):
    ret = "v???"
    if n == 769:
        ret = "v1.0"
    elif n == 770:
        ret = "v1.1"
    elif n == 771:
        ret = "v1.2"
    return ret
