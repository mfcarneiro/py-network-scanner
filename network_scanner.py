#! /user/bin/env python3

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Using srp because of this custom MAC Address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1)[0]

    display_scan_results(answered_list)


def display_scan_results(result_list):
    print('IP\t\t\tMAC Address\n-----------------------------------')
    for result in result_list:
        print(result[1].psrc + '\t\t' + result[1].hwsrc)


scan("192.168.1.0/24")
