#!usr/bin/env python

import scapy.all as scapy
import pprint
import argparse

def get_arguments ():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="range", help="Please specify an IP Range.")
    options = parser.parse_args()

    if not options.range:
        parser.error("Please specify an IP Range. For more enter --help")
    return options

def scan (ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")

    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
options = get_arguments()
scan_result = scan(options.range)
print_result(scan_result)


