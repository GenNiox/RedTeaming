#!/usr/bin/env python3

import argparse
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip-address", dest="ip_address", help="IP Address range to scan (i.e. 10.1.1.1)")
    parser.add_argument("-s", "--subnet-mask", dest="subnet_mask", help="Subnet CIDR notation integer to scan (i.e. 24)")
    options = parser.parse_args()
    if not options.ip_address:
        parser.error("[-] Please specify an IP Address, use --help for more info.")
    if not options.subnet_mask:
        parser.error("[-] Please specify a Subnet mask in CIDR notation, use --help for more info.")
    return options


def scan(ip_address, subnet_mask):
    ip = str(ip_address) + "/" + str(subnet_mask)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # srp allows custom addresses.

    response_list = []
    for answer in answered_list:
        response_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        response_list.append(response_dict)
    return response_list


def print_result(results_list):
    print("=================================================")
    print("|\tIP:\t\t\t\t\t\tMAC Address:\t\t|")
    print("=================================================")
    for answer in results_list:
        print("|\t" + answer["ip"] + "  " + "\t\t\t" + answer["mac"] + "\t|")
        print("-------------------------------------------------")

    # scapy.ls(scapy.ARP())  # For help if needed
    # print(arp_request.summary())
    # scapy.ls(scapy.Ether())  # For help if needed
    # print(broadcast.summary())
    # print(arp_request_broadcast.summary())
    # arp_request.show()
    # broadcast.show()
    # arp_request_broadcast.show()
    # print(answered_list.summary())
    # print(unanswered_list.summary())
    # print(answer[1].psrc)
    # print(answer[1].hwsrc)

# valid = False
# ip_to_scan = input("IP Range to scan (IP.IP.IP.IP/SM): ")


options = get_arguments()
scan_result = scan(options.ip_address, options.subnet_mask)
print_result(scan_result)
