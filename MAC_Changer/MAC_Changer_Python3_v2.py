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
    parser.add_argument("-m", "--mac", "--mac-address", dest="newMAC", required=False, help="Desired MAC Address; used with '-t c'")
    parser.add_argument("-t", "--type", dest="mac_change_type", help="Type of MAC Address change (i.e. (c)ustom or (v)endor")
    (options) = parser.parse_args()  # Include once at the end
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    if not options.mac_change_type:
        parser.error("[-] Please specify a MAC Address change type, use --help for more info.")
    if not options.mac_change_type == "c" and not options.mac_change_type == "C" and not options.mac_change_type == "v" and not options.mac_change_type == "V":
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


def get_vendor_list(vendor):
    vendor_exists = 0
    cwd = os.path.dirname(os.path.realpath(__file__))
    text_file = cwd + "/Vendor_MAC_Files/" + str(vendor) + ".txt"
    if not os.path.exists(text_file):
        if len(vendor) <= 3:
            print("[-] No " + str(vendor) + " file!  \t(" + cwd + "/Vendor_MAC_Files/" + str(vendor) + ".txt)")
        else:
            print("[-] No " + str(vendor) + " file!\t(" + cwd + "/Vendor_MAC_Files/" + str(vendor) + ".txt)")
    else:
        print("[+] " + str(vendor) + " file detected!")
        vendor_exists = vendor
        if not vendor_exists == 0:
            return vendor
        else:
            vendor = 0
            return vendor


options = get_arguments()
if options.mac_change_type == "v" or options.mac_change_type == "V":
    vendor_list = ["Juniper", "Cisco", "Brocade", "HP", "Netgear", "TP-Link", "ASUS", "Motorola", "Synology", "Linksys"]
    print("[+] Loading Vendor MAC Addresses..")
    vendor_list_usable = []
    for vendor in vendor_list:
        get_vendor_list(vendor)  # File names *MUST* match the vendor_list names (case-sensitive!)
        if not vendor == 0:
            vendor_list_usable.append(vendor)
    print("===================")
    print("[+] Vendor List:  |")
    print("===================")
    for vendor in vendor_list_usable:
        print("[+] " + vendor)
    vendor_list_choice = input("Select a vendor from the list (Case-sensitive!): ")
    cwd = os.path.dirname(os.path.realpath(__file__))
    text_file_choice = cwd + "/Vendor_MAC_Files/" + str(vendor_list_choice) + ".txt"
    text_file_choice_open = open(text_file_choice, "r")
    text_file_choice_text = text_file_choice_open.read()
    counter = 0
    re_mac_list = re.findall(r"\w\w:\w\w:\w\w", str(text_file_choice_text))
    for vendor_mac in re_mac_list:
        counter = counter + 1
        print(str(counter) + " --> " + vendor_mac)
    text_file_choice_open.close()


# 1. Import Various Vendor Models Text Files
#       Using link: https://www.wireshark.org/tools/oui-lookup.html
# 2. Select a Vendor Prefix (XX:XX:XX)
# 3. Randomly select a Prefix from the List
# 4. Create the second-half of the MAC Address

elif options.mac_change_type == "c" or options.mac_change_type == "C":
    if not options.newMAC:
        print("[-] No MAC Address specified!")
        exit(1)
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
