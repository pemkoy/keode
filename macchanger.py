import subprocess
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change Mac Address")
    parser.add_argument("-m", "--macaddr", dest="macaddr", help="New Mac Address")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface. Use --help for more information.")
    elif not options.macaddr:
        parser.error("[-] Please specify a mac address. Use --help for more information.")
    return options

def get_current_mac(inteface):
    ifconfig_result = subprocess.check_output(["ifconfig", options.interface], stderr=subprocess.STDOUT)
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    return mac_address_search_result.group(0)

def change_macaddr(iface, macaddr):
    print("[+] Changing Mac Address for "+iface+" to "+macaddr)
    subprocess.call(["ifconfig",iface,"down"])
    subprocess.call(["ifconfig",iface,"hw","ether", macaddr]) 
    subprocess.call(["ifconfig",iface,"up"])

print("--------------------------------------------------")
print("|\t macchanger.py - keode by relofa\t |")
print("--------------------------------------------------")

try:        
    options = get_arguments()
    old_mac = get_current_mac(options.interface)
    print("[+] Old Mac = "+old_mac)

    change_macaddr(options.interface, options.macaddr)
    new_mac = get_current_mac(options.interface)

    if old_mac != new_mac:
        print("[+] New Mac = "+new_mac)
    else:
        print("[-] Mac Address did not get change")

except subprocess.CalledProcessError:
    print("\r[-] Unknown Arguments")

except :
    print("[-] Exit macchanger.py - keode by relofa")