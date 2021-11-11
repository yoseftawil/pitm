#!usr/bin/env python
import netfilterqueue
import subprocess

def process_packet(packet):
    print(packet)
    packet.drop()


subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()