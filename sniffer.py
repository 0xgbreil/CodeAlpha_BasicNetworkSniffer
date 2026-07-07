from scapy.all import *
import socket
from datetime import datetime
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def get_serv(src_port, dst_port):
    try:
        return socket.getservbyport(src_port)
    except OSError:
        try:
            return socket.getservbyport(dst_port)
        except OSError:
            return "Unknown"


def analyzer(PKT):
    try:
        if not PKT.haslayer(IP):
            return

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        src_ip = PKT[IP].src
        dst_ip = PKT[IP].dst
        src_mac = PKT.src
        dst_mac = PKT.dst

        print(Fore.WHITE + "=" * 60)
        print(Fore.GREEN + f"Time : {current_time}")

        if PKT.haslayer(ICMP):
            print(Fore.RED + "Protocol            : ICMP")
            print(Fore.CYAN + f"Source IP           : {Fore.WHITE}{src_ip}")
            print(Fore.CYAN + f"Destination IP      : {Fore.WHITE}{dst_ip}")
            print(Fore.CYAN + f"Source MAC          : {Fore.WHITE}{src_mac}")
            print(Fore.CYAN + f"Destination MAC     : {Fore.WHITE}{dst_mac}")
            print(Fore.CYAN + f"Packet Size         : {Fore.WHITE}{len(PKT[ICMP])} Bytes")

            if PKT.haslayer(Raw):
                try:
                    payload = PKT[Raw].load.decode("utf-8")
                except UnicodeDecodeError:
                    payload = PKT[Raw].load

            print(Fore.WHITE + f"Payload:\n{payload}")

        elif PKT.haslayer(TCP):

            src_port = PKT[TCP].sport
            dst_port = PKT[TCP].dport
            service = get_serv(src_port, dst_port)

            print(Fore.BLUE + "Protocol            : TCP")
            print(Fore.CYAN + f"Source IP           : {Fore.WHITE}{src_ip}")
            print(Fore.CYAN + f"Destination IP      : {Fore.WHITE}{dst_ip}")
            print(Fore.CYAN + f"Source MAC          : {Fore.WHITE}{src_mac}")
            print(Fore.CYAN + f"Destination MAC     : {Fore.WHITE}{dst_mac}")
            print(Fore.CYAN + f"Source Port         : {Fore.WHITE}{src_port}")
            print(Fore.CYAN + f"Destination Port    : {Fore.WHITE}{dst_port}")
            print(Fore.CYAN + f"Service             : {Fore.WHITE}{service}")
            print(Fore.CYAN + f"Packet Size         : {Fore.WHITE}{len(PKT[TCP])} Bytes")

            if PKT.haslayer(Raw):
                try:
                    payload = PKT[Raw].load.decode("utf-8")
                except UnicodeDecodeError:
                    payload = PKT[Raw].load

            print(Fore.WHITE + f"Payload:\n{payload}")


        elif PKT.haslayer(UDP):

            src_port = PKT[UDP].sport
            dst_port = PKT[UDP].dport
            service = get_serv(src_port, dst_port)

            print(Fore.YELLOW + "Protocol            : UDP")
            print(Fore.CYAN + f"Source IP           : {Fore.WHITE}{src_ip}")
            print(Fore.CYAN + f"Destination IP      : {Fore.WHITE}{dst_ip}")
            print(Fore.CYAN + f"Source MAC          : {Fore.WHITE}{src_mac}")
            print(Fore.CYAN + f"Destination MAC     : {Fore.WHITE}{dst_mac}")
            print(Fore.CYAN + f"Source Port         : {Fore.WHITE}{src_port}")
            print(Fore.CYAN + f"Destination Port    : {Fore.WHITE}{dst_port}")
            print(Fore.CYAN + f"Service             : {Fore.WHITE}{service}")
            print(Fore.CYAN + f"Packet Size         : {Fore.WHITE}{len(PKT[UDP])} Bytes")

            if PKT.haslayer(Raw):
                try:
                    payload = PKT[Raw].load.decode("utf-8")
                except UnicodeDecodeError:
                    payload = PKT[Raw].load

            print(Fore.WHITE + f"Payload:\n{payload}")

    except Exception:
        return


print(Fore.GREEN + "=" * 60)
print(Style.BRIGHT + Fore.GREEN  + "             Basic Network Sniffer")
print(Fore.CYAN + "                 By 0xgbreil")
print(Fore.GREEN + "=" * 60)
print(Fore.GREEN + "[+] Initializing...")
print(Fore.GREEN + "[+] Loading Scapy...")
print(Fore.GREEN + "[+] Listening for network packets...")
print(Fore.GREEN + "[+] Press Ctrl + C to stop the program.")
print(Fore.GREEN + "=" * 60)

try:
    

    interfaces = get_if_list()

    print(Fore.GREEN + "\nAvailable Network Interfaces:\n")

    for index, iface in enumerate(interfaces, start=1):
        print(f"{Fore.CYAN}[{index}] {Fore.YELLOW}{iface}")

    print(Fore.RED + "\n[99] Exit")

    while True:

        choice = input(Fore.GREEN + "\nSelect an interface number: " + Fore.WHITE).strip()

        if not choice:
            print(Fore.RED + "[!] Input cannot be empty.")
            continue

        if not choice.isdigit():
            print(Fore.RED + "[!] Please enter a valid number.")
            continue

        choice = int(choice)

        if choice == 99:
            print(Fore.RED + "\n[+] Exiting Basic Network Sniffer...")
            sys.exit()

        if choice < 1 or choice > len(interfaces):
            print(Fore.RED + "[!] Invalid interface number.")
            continue

        interface = interfaces[choice - 1]
        break

    print(Fore.GREEN + f"\n[+] Selected Interface: {Fore.YELLOW}{interface}")
    print(Fore.GREEN + f"[+] Starting packet capture on interface: {Fore.YELLOW}{interface}\n")
    sniff(iface=interface, prn=analyzer, store=False)    

finally:
    print(Fore.RED +"\n[+] Sniffer stopped successfully.")
