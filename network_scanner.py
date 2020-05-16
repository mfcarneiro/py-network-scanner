#! /usr/bin/env python3

import argparse
import scapy.all as scapy


def init_banner():
    arguments = get_user_arguments()
    scanner_result = scan(arguments.target)
    display_scan_results(scanner_result)


def get_user_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='IP of the target')
    arguments = parser.parse_args()

    return arguments


def scan(ip):
    client_list = []
    arp_request = scapy.ARP(pdst=ip)
    # Using srp because of this custom MAC Address
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    for result in answered_list:
        answered_dictionary = {'ip': result[1].psrc, 'mac': result[1].hwsrc}
        client_list.append(answered_dictionary)

    return client_list


def display_scan_results(result_list):
    print('IP\t\t\tMAC Address\n-----------------------------------')

    for client in result_list:
        print(client['ip'] + '\t\t' + client['mac'])

