import socket
import threading
import concurrent.futures
import colorama
import logging 

from colorama import Fore
import argparse
from scapy.all import *
from scapy.all import sniff
logging.basicConfig(filename="logging.log", 
					format='%(asctime)s %(message)s', 
					filemode='a') 
logger=logging.getLogger()
logger.setLevel(logging.DEBUG) 



def arp_scan(ip):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(request, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})
    return result



def tcp_scan():
    colorama.init(autoreset=True)
    print_lock = threading.Lock()
    ip = input("Enter ip address to scan: ")
    def scan(ip, port=None):
        scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scanner.settimeout(1)
        try:
            scanner.connect((ip, port))
            scanner.close()
            with print_lock:
                print(Fore.GREEN + f"Portt {port} is open")
                logger.info("Output of TCP scan: " +  f"Port {port} of host {ip} is open")

        except:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1, 1024):
            executor.submit(scan, ip, port+12)


def main():
    # if length of arguments is 0 then print help
    if len(sys.argv) == 1:
        print("To use commandline arguments use the -h to get help (python host-discovery ARP -h) ")
        print("Which scan do you want to perform?")
        print("1. ARP Scan")
        print("2. TCP Scan")
        print("3. OS Detection")
        print("4. Pcap Sniffing")
        print("5. Exit")
        choice = input("Enter your choice: ")
        os.system("clear && printf '\e[3J'")
        if choice == "1":
            ip = input("Enter ip address to scan: ")
            mask = input("Enter subnet mask (/16,/24): ")
            ip = ip + mask
            print(ip)
            result = arp_scan(ip)
            print_arp(result)
            logger.info("Output of ARP scan: " + str(result))

            sys.exit()
        elif choice == "2":
            tcp_scan()
        elif choice == "3":
            os_detection()
            sys.exit()
        elif choice == "4":
            pcap_sniffing()
            sys.exit()
        elif choice == "5":
            sys.exit()
        else:
            print("Invalid choice")     
            sys.exit()
    # parse the arguments
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="command", help="Command to perform.", required=True
    )

    arp_subparser = subparsers.add_parser(
        'ARP', help='Perform a network scan using ARP requests.'
    )
    arp_subparser.add_argument(
        'IP', help='An IP address (e.g. 192.168.1.1) or address range (e.g. 192.168.1.1/24) to scan.'
    )

    tcp_subparser = subparsers.add_parser(
        'TCP', help='Perform a TCP scan using SYN packets.'
    )
    tcp_subparser.add_argument('IP', help='An IP address or hostname to target.')
    args = parser.parse_args()
    if args.command == 'ARP':
        result = arp_scan(args.IP)  
        print_arp(result)
    elif args.command == 'TCP':
        ports = [0,1024]
        try:
            result = tcp_scan()
        except ValueError as error:
            print(error)
            exit(1)
    else:
        pass
def print_arp(result):
    for mapping in result:
        print('{} ==> {}'.format(mapping['IP'], mapping['MAC']))
def os_detection():
    
    from scapy.layers.inet import IP, ICMP

    os = ''
    target = input("Enter the IP address:  ")
    pack = IP(dst=target)/ICMP()
    resp = sr1(pack, timeout=3)
    if resp:
        if IP in resp:
            ttl = resp.getlayer(IP).ttl
            if ttl <= 64: 
                os = 'Linux'
            elif ttl > 64:
                os = 'Windows'
            else:
                print('Not Found')
            logger.info(f"Output of os detect scan: " + os + " Operating System Is Detected On " + target)
            print(f'\n\nTTL = {ttl} \n*{os}* Operating System is Detected \n\n')

def pcap_sniffing():
    import socket
    import os
    import sys
    import struct

    # host to listen on
    host = ""
    # http-verkeer (smtp, pop33, imap)
    sniff(prn=packet_callback, count=1)

def packet_callback(packet):
    print(packet.show())
    logger.info("Output of pcap sniffing: " + str(packet.show()))


if __name__ == '__main__':
    main()
