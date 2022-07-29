from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest,TCP
from colorama import init, Fore
def banner():
    print("""%s
             |     ---|----- ---------  -------------- |-------  ||     | |------- |-------|
             |        |      |                |        |         | |    | |        |       |
             |        |      |                |        |         |  |   | |------- |-------|
             |        |      |--------|       |        |-------  |   |  | |        | |
             |        |               |       |        |         |    | | |        |  |
             |---- ---|----  ---------|       |        |-------- |     || |------- |   |
                                                                                        |
             @Developed by - Mayank Pal              
                           """)
banner()
print("1:Raw network packet scanning")
print("2:HTTP header disection")
init()
red=Fore.RED
green=Fore.GREEN
yellow=Fore.YELLOW
reset=Fore.RESET
def packetsniff(iface):
    sniff(iface='eth0',prn=packetloader)
def packetloader(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[IP].dport
        src_port = packet[IP].sport
        print(f"{green}[+] {src_ip} is using {src_port} port to interct with {dst_ip} on {dst_port}")
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method=packet[HTTPRequest].Method.decode()

        print(f"{yellow}[+]{src_ip} tried to connect with {url} using {method} method")
        print("HTTP HEADER:")
        print(f"{yellow}[+] {packet[HTTPRequest].show()}")
        if packet.haslayer(Raw):
            print(f"{red}[+]Confedential info:")
            print(f"{red}[+]Confedential info:{packet.getlayer(Raw).load.decode()}{reset}")
take=int(input())
if take == 1:

    no_of_packets=int(input('How many packets do you want to sniff'))
    print("What kind of packets packets")
    print("1:TCP")
    print("2:ARP")
    print("3:IP/HTTP Request")
    print("4:ICMP")
    print("5:ALL")
    type_of_packet=int(input())
    if type_of_packet==1:
        print("Press ctrl+c to end sniffing and look at results")
        a=sniff(filter="tcp",iface='eth0', count=no_of_packets)
        a.summary()
    elif type_of_packet==2:
        print("Press ctrl+c to end sniffing and look at results")
        a=sniff(filter="arp",iface='eth0',count=no_of_packets)
        a.summary()
    elif type_of_packet==3:
        print("Press ctrl+c to end sniffing and look at results")
        a=sniff(filter=HTTPRequest,iface='eth0',count=no_of_packets)
        a.summary()
    elif type_of_packet==4:
        print("Press ctrl+c to end sniffing and look at results")
        a=sniff(filter="icmp",iface='eth0',count=no_of_packets)
    elif type_of_packet==5:
        print("Press ctrl+c to end sniffing and look at results")
        a=sniff(iface='eth0',count=no_of_packets)
        a.summary()

elif take == 2:
    packetsniff('eth0')


