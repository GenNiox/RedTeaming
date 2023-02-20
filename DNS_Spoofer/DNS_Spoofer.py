#!/usr/bin/env python3
import argparse
import scapy.all as scapy
import netfilterqueue


# Kali Commands:
# iptables -I FORWARD -j NFQUEUE --queue-num 0  # For forwarded (remote machine) packet testing
# sudo apt install libnetfilter-queue-dev libnetfilter-queue1
# pip3 install netfilterqueue
# iptables --flush  # Once finished with packet interception


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--queue-number", dest="queue_number", help="Setup via the iptables --queue-num switch)")
    options = parser.parse_args()
    if not options.queue_number:
        parser.error("[-] Please specify a queue number, see --help for more info.")
    return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())
    # packet.accept()  # Forwards packets
    # packet.drop()  # Drops packets


options = get_arguments()
print("[+] Initiating DNS Spoofer..")
print("[+] Setting up NetfilterQueue..")
queue = netfilterqueue.NetfilterQueue()
queue.bind(int(options.queue_number), process_packet)
print("[+] Spoofing DNS of queue number " + str(options.queue_number))
queue.run()

