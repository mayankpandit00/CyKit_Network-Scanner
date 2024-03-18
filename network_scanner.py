import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import optparse
import re


def get_scan_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range")
    (arguments, options) = parser.parse_args()
    if not arguments.target or not bool(re.match(r"^(?:\d{1,3}\.){3}(?:\d{1,3}|\d/\d{2})$", arguments.target)):
        print("[-] Invalid input; Please specify a target; Use -h or --help for more info")
        exit(0)
    else:
        return arguments


def scan_network(ip):
    answered_arp_request_list = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)[0]
    clients_list = []
    for request, response in answered_arp_request_list:
        clients_dict = {"ip": response.psrc, "mac": response.hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def display_results(results_list):
    print(" ------------------------------------------\n    IP Address\t\t   MAC Address\n ------------------------------------------\n")
    for result in results_list:
        print("[+] " + result["ip"] + "\t\t" + result["mac"])


arguments = get_scan_arguments()
scan_results = scan_network(arguments.target)
display_results(scan_results)
