#!/usr/bin/env python3


import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff from (i.e. wlan0)")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface to sniff from, see --help for more info.")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet())


def process_sniffed_packet(packet):
    print(packet)


options = get_arguments()
sniff(options.interface)
