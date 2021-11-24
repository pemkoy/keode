from scapy import all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP / IP range. Use --help for more information.")
        
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    brdcast = scapy.Ether(dst="bb:bb:bb:bb:bb:bb")
    arp_req_brdcast = brdcast/arp_req
    answrd_lst = scapy.srp(arp_req_brdcast, timeout=1, verbose=False)[0]

    print("--------------------------------------------------")
    print("|\t netscanner.py - keode by relofa\t |")
    print("--------------------------------------------------")

    client_lst = []
    for el in answrd_lst:
        client_dct = {'ip' : el[1].psrc, 'mac' : el[1].hwsrc}
        client_lst.append(client_dct)

    return client_lst

def print_result(result_lst):
    print("No\tIP\t\t\tMac Address")

    num=1
    for client in result_lst:
        print(str(num)+".\t"+client["ip"]+"\t\t"+client["mac"],end="\n")
        num+=1

try:        
    options = get_arguments()
    scan_result = scan(options.target)
    print_result(scan_result)
    
except :
    print("[-] Exit netscanner.py - keode by relofa")
