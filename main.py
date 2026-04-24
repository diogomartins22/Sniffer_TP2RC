"""Sniffer de pacotes em modo CLI com Scapy.

Este script faz captura direta e imprime uma tabela compacta ao estilo
Wireshark com tempo, origem, destino, protocolo, tamanho e resumo.
"""

from __future__ import annotations

import argparse 
import signal 
from datetime import datetime

from scapy.all import ARP, DNS, DHCP, Ether, ICMP, IP, IPv6, TCP, UDP, sniff # As cenas do scappy que precisamos


def detetar_protocolo(pct) -> str: # Deteta o protocolo da cena posso me ter esquecido de alguma cena
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


def extrair_caminho_pacote (pct) -> tuple[str, str]: #Extrai a origem e o destino da cena
    if pct.haslayer(ARP):
        return str(pct[ARP].psrc), str(pct[ARP].pdst)
    if pct.haslayer(IP):
        return str(pct[IP].src), str(pct[IP].dst)
    if pct.haslayer(IPv6):
        return str(pct[IPv6].src), str(pct[IPv6].dst)
    if pct.haslayer(Ether):
        return str(pct[Ether].src), str(pct[Ether].dst)
    return "?", "?"



def main() -> int:

    stop_capture = {"value": False}

    def tratar_sigint(_sig, _frame) -> None:
        stop_capture["value"] = True
        print("\nA parar captura...")

    signal.signal(signal.SIGINT, tratar_sigint)

    counter = {"value": 0}

    def ao_receber_pacote(pct) -> None:
        counter["value"] += 1

        sniff(
            prn=ao_receber_pacote,
            store=False,
            stop_filter=lambda _pct: stop_capture["value"],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
