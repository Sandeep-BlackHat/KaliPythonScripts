#!/usr/bin/env python

import datetime
import itertools
import optparse
import os
import re
import scapy.all as scapy
import sys
import threading
import time

done = False
start_time = datetime.datetime.now()


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("--t", "--target", dest="target", help="Target IP for Network Scanning. (ex: 192.168.1.1/24)")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    if not validate_ip(options.target):
        parser.error("[-] Please enter a valid IP Target. (ex: 192.168.1.1/24)")
    return options


def validate_ip(ip):
    global done
    # Group 0 = 192.168.1.1/24
    # Group 1 = 192.X.X.X/xx
    # Group 2 = X.168.X.X/xx
    # Group 3 = X.X.1.X/xx
    # Group 4 = X.X.X.1/xx
    # Group 5 = X.X.X.X/24
    address = re.search(r"((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(24))", ip)
    if address:
        for index, group in enumerate(address.groups()):
            if index is 0:
                continue
            if not validate_group(index, group):
                done = True
                return False
        return True
    done = True
    return False


def validate_group(index, group):
    int_value = int(group)
    if index is 5:
        return 0 <= int_value <= 32
    return 0 <= int_value <= 255


def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rloading ' + c)
        sys.stdout.flush()
        time.sleep(0.07)


def clear_screen():
    # for windows OS
    if os.name == "nt":
        os.system("cls")
    # for linux / Mac OS
    else:
        os.system("clear")


def scan(ip):
    # ARP
    arp_request = scapy.ARP(pdst=ip)
    # Ethernet Broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Packet
    arp_request_broadcast = broadcast/arp_request
    # Sending the packet / Receive the Response
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    clients = []
    global done
    done = True
    for client in answered_list:
        clients.append((client[1].psrc, client[1].hwsrc))
    return clients


def display_results(clients):
    duration = datetime.datetime.now() - start_time
    clear_screen()
    print('===network_scanner.py================================')
    print('IP\t\t\tMAC Address\n-----------------------------------------------------')
    for client in clients:
        print(client[0] + '\t\t' + client[1])
        print('-----------------------------------------------------')
    print('=====================================================')
    print('Done!')
    print(str(len(clients)) + ' Client Results\tDuration: ' + str(duration))


t = threading.Thread(target=animate)
t.start()
options = get_arguments()
print("The results are as follows: ",display_results(scan(options.target))
