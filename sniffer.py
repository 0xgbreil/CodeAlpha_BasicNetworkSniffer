from scapy.all import *
import socket
from datetime import datetime
import sys
from colorama import Fore, Style, init
import time
from banner import show_banner

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
        time.sleep(0.5)
        print(Fore.GREEN + f"Time : {current_time}")
        def get_payload(pkt):
            if pkt.haslayer(Raw):
                try:
                    return pkt[Raw].load.decode("utf-8")
                except UnicodeDecodeError:
                    return pkt[Raw].load
            return "No Payload"
        
        if PKT.haslayer(ICMP):
            print(Fore.RED + "Protocol            : ICMP")
            print(Fore.CYAN + f"Source IP           : {Fore.WHITE}{src_ip}")
            print(Fore.CYAN + f"Destination IP      : {Fore.WHITE}{dst_ip}")
            print(Fore.CYAN + f"Source MAC          : {Fore.WHITE}{src_mac}")
            print(Fore.CYAN + f"Destination MAC     : {Fore.WHITE}{dst_mac}")
            print(Fore.CYAN + f"Packet Size         : {Fore.WHITE}{len(PKT[ICMP])} Bytes")

            print(get_payload(PKT))

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

            print(get_payload(PKT))


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

            print(get_payload(PKT))

    except Exception:
        return


print(Fore.GREEN + "=" * 60)


show_banner()
print(Fore.GREEN + "=" * 60)
print(Fore.GREEN + "[+] Initializing...")
print(Fore.GREEN + "[+] Loading Scapy...")
print(Fore.GREEN + "[+] Listening for network packets...")
print(Fore.GREEN + "[+] Press Ctrl + C to stop the program.")
print(Fore.GREEN + "=" * 60)

try:
    

    interfaces = list(IFACES.values())

    print(Fore.GREEN + "\nAvailable Network Interfaces:\n")
    

    for index, iface in enumerate(interfaces, start=1):
        print(f"{Fore.CYAN}[{index}] {Fore.YELLOW}{iface.name}")
    print(Fore.RED + "[99] Exit") 

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
            print(Fore.RED + "\n[+] Sniffer stopped successfully.")
            sys.exit()

        if choice < 1 or choice > len(interfaces):
            print(Fore.RED + "[!] Invalid interface number.")
            continue

        interface = interfaces[choice - 1]
        break

    print(Fore.GREEN + f"\n[+] Selected Interface: {Fore.YELLOW}{interface}")
    print(Fore.GREEN + f"[+] Starting packet capture on interface: {Fore.YELLOW}{interface}\n")
    sniffer = AsyncSniffer(
        iface=interface,
        prn=analyzer,
        store=False
    )

    sniffer.start() 

    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print(Fore.RED + "\n[+] Stopping sniffer...")
    sniffer.stop()
    print(Fore.RED + "[+] Sniffer stopped successfully.")
    sys.exit()
