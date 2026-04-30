"""Sniffer de pacotes em modo CLI com Scapy."""
from __future__ import annotations
import argparse
import signal
from datetime import datetime
from scapy.all import sniff, Ether, IP, IPv6, ARP, ICMP, ICMPv6EchoRequest, TCP, UDP, DNS, DHCP

def detetar_protocolo(pct) -> str:
    if pct.haslayer(ARP):
        return "ARP"
    if pct.haslayer(DHCP):
        return "DHCP"
    if pct.haslayer(DNS):
        return "DNS"
    if pct.haslayer(ICMP):
        return "ICMP"
    if pct.haslayer(TCP):
        return "TCP"
    if pct.haslayer(UDP):
        return "UDP"
    if pct.haslayer(IP):
        return "IPv4"
    if pct.haslayer(IPv6):
        return "IPv6"
    if pct.haslayer(Ether):
        return "Ethernet"
    return "Outro"

def parse():
    parser = argparse.ArgumentParser(
        prog='LarpSniffer',
        description='Internet Packet Sniffer',
        epilog='Use --help for more info'
    )
    parser.add_argument('--qnt', type=int, help="número de pacotes")
    parser.add_argument('--prtl', type=str, help="protocolo a filtrar")
    parser.add_argument('--ip',nargs=2, metavar=('IP', 'src/dst'), help="filtrar por IP")
    parser.add_argument('--mac',nargs=2, metavar=('MAC', 'src/dst'), help="filtrar por MAC")
    parser.add_argument('--log', type=str, help="guardar pacotes num ficheiro")
    parser.add_argument('--live', action='store_true', help="mostrar pacotes no terminal")

    args = parser.parse_args()

    return args

def printPacote(tempo, iface, size, protocol, src_mac, dst_mac, src_ip, dst_ip, pkt, ip, mac):
    #testa se tem --mac primeiro se não tiver dá default para o IP 
    if mac and Ether in pkt:
        print(f"{tempo:<20} {src_mac:<20} {dst_mac:<20} {protocol:<10} {size}")
    elif IP in pkt:
        print(f"{tempo:<20} {src_ip:<20} {dst_ip:<20} {protocol:<10} {size}")
    elif Ether in pkt:
        print(f"{tempo:<20} {src_mac:<20} {dst_mac:<20} {protocol:<10} {size}")



def filtro (prtl, ip, mac, protocol, src_mac, dst_mac, src_ip, dst_ip) -> bool:
    if prtl:
        if prtl != protocol: return False
    
    if ip:
        if ip[1] == "src":
            if ip[0] != src_ip:return False
        elif ip[1] == "dst":
            if ip[0] != dst_ip:return False

    if mac:
        if mac[1] == "src":
            if mac[0] != mac_ip:return False
        elif mac[1] == "dst":
            if mac[0] != mac_ip:return False
    return True

    

def sniffer(qnt, prtl, ip, mac, log, live):
    i = 0
    while i < qnt:
        pkts = sniff(count=1)
        pkt = pkts[0]
        #data/hora do pacote
        tempo = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3] #passar de timestamp para tempo
        
        #interface
        iface = pkt.sniffed_on

        # Tamanho
        size = len(pkt)

        #protocol
        protocol = detetar_protocolo(pkt)

        # MAC addresses
        if Ether in pkt:
            src_mac = pkt[Ether].src 
        else: src_mac = "?" 
        if Ether in pkt:
            dst_mac = pkt[Ether].dst
        else: dst_mac = "?" 


        # IP addresses
        if IP in pkt:
            src_ip = pkt[IP].src 
        else: src_ip = "?" 
        if IP in pkt:
            dst_ip = pkt[IP].dst
        else: dst_ip = "?" 

        #falta o resumo do conteúdo (ex.: “ARP request”, “ICMP echo request”, “DHCP Discover”, etc.) depois vê-se

        #metemos os filtros no print pacotes acho eu, ou então mal se vê o protocol e isso verifica logo se entra no filtro e
        #para logo o código com break ou o caralho
        if filtro(prtl, ip, mac, protocol, src_mac, dst_mac, src_ip, dst_ip):
            printPacote(tempo, iface, size, protocol, src_mac, dst_mac, src_ip, dst_ip, pkt, ip, mac)
            i += 1  # só conta se passar no filtro

    



def main() -> int:
    args = parse()
    if args is None:
        return 0

    print(f"{"Tempo":<20} {"Origem":<20} {"Destino":<20} {"Protocolo":<10} {"Tamanho"}")
    sniffer(args.qnt, args.prtl, args.ip, args.mac, args.log, args.live)


    stop_capture = {"value": False}

    def tratar_sigint(_sig, _frame) -> None:
        stop_capture["value"] = True
        print("\nA parar captura...")

    signal.signal(signal.SIGINT, tratar_sigint)
    return 0


if __name__ == "__main__":
    main()