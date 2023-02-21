#!/usr/bin/env python3
# Created by: GenNiox
# Last modified: 17FEB2023
# Credit goes to zSecurity's Udemy course for teaching me the knowledge to create this script. Definitely check him out.
# Link: https://www.udemy.com/course/learn-python-and-ethical-hacking-from-scratch/
# DISCLAIMER:   This script is to be used for ethical *AND* legal purposes only.
#               You may use, modify, and spin-off of this script if you wish.
#               Hack on, Brothers.
#
#                 |
#                 ^
#               \/G\/
#               / V \
#
# Tasklist:
# [ ] Import various vendor models
#    [ ] Juniper
#    [ ] Cisco
#    [ ] Brocade
#    [ ] HP
#    [ ] NetGear
#    [ ] TP-Link
#    [ ] ASUS
#    [ ] Motorola
#    [ ] Synology
#    [ ] Linksys

#
# Notes:
# If you need this script to run in Python v2:
#       [ ] Change all "input()"s to "raw_input()"s
# Research:
# Links:
# https://stackoverflow.com/questions/43007979/how-to-import-txt-file-into-python
# https://docs.python.org/3/library/random.html
# ("random.randrange")


import subprocess
import argparse  # Allows for command-line argument structure
import re
import os

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Changes the MAC Address of the specified interface")
    parser.add_argument("-m", "--mac", "--mac-address", dest="newMAC", required=False, help="Desired MAC Address; used with '-m c'")
    parser.add_argument("-t", "--type", dest="mac_change_type", help="Type of MAC Address change (i.e. (c)ustom or (v)endor")
    (options) = parser.parse_args()  # Include once at the end
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    if not options.mac_change_type:
        parser.error("[-] Please specify a MAC Address change type, use --help for more info.")
    if not options.newMAC == "c" or options.newMAC == "C" or options.newMAC == "v" or options.newMAC == "V":
        parser.error("[-] Invalid MAC Address change type, use --help for more info.")
    return options

def change_mac (interface, newmac):
    print("[+] Disabling interface: " + interface)
    subprocess.call(["ifconfig", interface, "down"])
    print("[+] Disabled interface: " + interface)
    subprocess.call(["ifconfig", interface, "hw", "ether", newmac])
    print("[+] Enabling interface: " + interface)
    subprocess.call(["ifconfig", interface, "up"])
    print("[+] Enabled interface: " + interface)


def detect_mac (interface):
    ifconfig_postresult = subprocess.check_output(["ifconfig", interface])
    mac_address_re_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_postresult))
    if mac_address_re_search_result:
        return mac_address_re_search_result.group(0)
    else:
        print("[-] MAC_Changer threw an error when detecting a MAC Address!")


options = get_arguments()
if options.mac_change_type == "v" or options.mac_change_type == "V":
    print("[+] Loading Vendor MAC Addresses..")
    text_file_juniper = open(os.getcwd("/Vendor_MAC_Files/Juniper.txt"))
    print(text_file_juniper)
# 1. Import Various Vendor Models Text Files
#       Using link: https://www.wireshark.org/tools/oui-lookup.html
# 2. Select a Vendor Prefix (XX:XX:XX)
# 3. Randomly select a Prefix from the List
# 4. Create the second-half of the MAC Address

elif options.mac_change_type == "c" or options.mac_change_type == "C":
    valid_mac_check = re.findall(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w"), str(options.newMAC)
    if valid_mac_check:
        old_current_mac = detect_mac(options.interface)
        print("[+] Initiating MAC Address Change..")
        change_mac(options.interface, options.newmac)
        print("[+] Executed MAC Address Change")
        new_current_mac = detect_mac(options.interface)
        print("[+] Validating MAC Address..")
        if new_current_mac == options.newMAC:
            print("[+] Validated MAC Address on " + options.interface + "!")
            print("[+] Old MAC Address: " + str(old_current_mac))
            print("[+] New MAC Address: " + str(new_current_mac))
        else:
            print("[-] Error when changing MAC Address..")
            print("[-] Old MAC: " + str(old_current_mac))
            print("[-] New MAC: " + str(new_current_mac))
    else:
        print("[-] Not a valid MAC Address!")
        exit("1")
