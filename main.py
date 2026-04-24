"""Sniffer de pacotes em modo CLI com Scapy."""
from __future__ import annotations
import argparse
import signal
from datetime import datetime
from scapy.all import ARP, DNS, DHCP, Ether, ICMP, IP, IPv6, TCP, UDP, sniff


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


def extrair_caminho_pacote(pct) -> tuple[str, str]:
    if pct.haslayer(ARP):
        return str(pct[ARP].psrc), str(pct[ARP].pdst)
    if pct.haslayer(IP):
        return str(pct[IP].src), str(pct[IP].dst)
    if pct.haslayer(IPv6):
        return str(pct[IPv6].src), str(pct[IPv6].dst)
    if pct.haslayer(Ether):
        return str(pct[Ether].src), str(pct[Ether].dst)
    return "?", "?"


def parse():
    parser = argparse.ArgumentParser(
        prog='LarpSniffer',
        description='Internet Packet Sniffer',
        epilog='Use --help for more info'
    )
    parser.add_argument('--qnt', type=int, help="número de pacotes")
    parser.add_argument('--prlt', type=str, help="protocolo a filtrar")
    parser.add_argument('--ip', type=str, help="filtrar por IP")
    parser.add_argument('--mac', type=str, help="filtrar por MAC")
    parser.add_argument('--log', type=str, help="guardar pacotes num ficheiro")
    parser.add_argument('--live', action='store_true', help="mostrar pacotes no terminal")

    args = parser.parse_args()

    return args


def sniffer(qnt, prlt, ip, mac, log, live):
    for i in range(0, qnt):
        packets = sniff(count=1)
        packets.summary()
    



def main() -> int:
    args = parse()
    if args is None:
        return 0

    sniffer(args.qnt, args.prlt, args.ip, args.mac, args.log, args.live)
    stop_capture = {"value": False}

    def tratar_sigint(_sig, _frame) -> None:
        stop_capture["value"] = True
        print("\nA parar captura...")

    signal.signal(signal.SIGINT, tratar_sigint)
    return 0


if __name__ == "__main__":
    main()