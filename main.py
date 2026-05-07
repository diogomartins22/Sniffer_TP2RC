"""Sniffer de pacotes em modo CLI com Scapy."""
from __future__ import annotations
import argparse
import signal
from datetime import datetime
from scapy.all import sniff, Ether, IP, IPv6, ARP, ICMP, TCP, UDP, DNS, DHCP
import csv

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
        try:
            sport = int(pct[TCP].sport)
            dport = int(pct[TCP].dport)
        except Exception:
            sport = dport = None
        if sport in (80, 8080) or dport in (80, 8080):
            return "HTTP"
        if sport in (443,) or dport in (443,):
            return "HTTPS"
        return "TCP"
    if pct.haslayer(UDP):        
        return "UDP"
    if pct.haslayer(IP):
        return "IPv4"
    return "Outro"

def conteudo_protocolo(pct) -> str:
    if pct.haslayer(ARP):
        if pct[ARP].op == 1:
            return "ARP request"
        elif pct[ARP].op == 2:
            return "ARP reply"

    if pct.haslayer(DHCP):
            return pct[DHCP].options
        
    if pct.haslayer(DNS):
        if pct[DNS].qr == 0:
            qr = "DNS query"
        elif pct[DNS].qr == 1:
            qr = "DNS request"
        return f"{qr}   id = {pct[DNS].id}  qdCount = {pct[DNS].qdcount}  anCount = {pct[DNS].ancount}"
    
    if pct.haslayer(ICMP):
        if pct[ICMP].type == 8 :
            tipo = "ICMP echo request"
        elif pct[ICMP].type == 0:
            tipo = "ICMP echo reply"
        else:
            tipo = "ICMP"
        return f"{tipo}   Code = {pct[ICMP].code}  Id = {pct[ICMP].id}  Seq = {pct[ICMP].seq}  Checksum = {pct[ICMP].chksum}"
        
    if pct.haslayer(TCP):
        flag = pct[TCP].flags
        f = ""
        if flag == "A":
            f = "[ACK]"
        elif flag == "S":
            f = "[SYN]"
        elif flag == "F":
            f = "[FIN]"
        elif flag == "P":
            f = "[PSH]"
        elif flag == "PA":
            f = "[PSH-ACK]"
        elif flag == "SA":
            f = "[SYN-ACK]"
        elif flag == "R":
            f = "[RST]"
        return f"{f}   Seq = {pct[TCP].seq}  Ack = {pct[TCP].ack}  Win = {pct[TCP].window}  Checksum = {pct[TCP].chksum}"
    
    if pct.haslayer(UDP):
        return f"Length = {pct[UDP].len}  Checksum = {pct[UDP].chksum}"

    if pct.haslayer(IP):
        flag = pct[IP].flags
        if not flag :
            flag = "0"
        return f"TTL = {pct[IP].ttl}  Flag = {flag}  Len = {pct[IP].len}  Checksum = {pct[IP].chksum}"
    
    if pct.haslayer(IPv6):
        return f"Hope Limit = {pct[IPv6].hlim}  Next Header = {pct[IPv6].nh}  Payload Length = {pct[IPv6].plen}"
    
    return ""

def parse():
    parser = argparse.ArgumentParser(
        prog='LarpSniffer',
        description='----- Internet Packet Sniffer -----',
        epilog='Use --help for more info'
    )
    parser.add_argument('--qnt', type=int, help="captura QNT pacotes")
    parser.add_argument('--prtl', type=str, help="filtrar por protocolo")
    parser.add_argument('--ip',nargs=2, metavar=('IP', 'src/dst'), help="filtrar por IP")
    parser.add_argument('--mac',nargs=2, metavar=('MAC', 'src/dst'), help="filtrar por MAC")
    parser.add_argument('--log', type=str, help="guardar num ficheiro .txt ou .csv")
    parser.add_argument('--live', action='store_true', help="captura contínua de pacotes (Default)")
    parser.add_argument('--iface', type=str, help="interface a usar para captura (ex: eth0, wlan0, lo)")

    args = parser.parse_args()

    if not args.live:
        if (not args.log and args.qnt) or (not args.log and not args.qnt):
            args.live = True

    return args

def printPacote(i, tempo, size, protocol, src_mac, dst_mac, src_ip, dst_ip, pkt, mac, info, live, qnt) -> str:
    #testa se tem --mac primeiro se não tiver dá default para o IP 
    if mac and Ether in pkt:
        src = src_mac
        dst = dst_mac
    elif IP in pkt:
        src = src_ip
        dst = dst_ip
    elif Ether in pkt:
        src = src_mac
        dst = dst_mac
    else: 
        src = "?"
        dst = "?"
    
    p = f"{i+1:<5}{tempo:<20} {src:<20} {dst:<20} {protocol:<10} {size:<10} {info}"

    if live :
       print(p)

    dados = [i+1, tempo, src, dst, protocol, size, info]
    return p, dados

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
            if mac[0] != src_mac:return False
        elif mac[1] == "dst":
            if mac[0] != dst_mac:return False
    return True

def logs(nomeFicheiro, p, log):
    if log == ".txt":
        with open(nomeFicheiro, 'a') as f:
            f.write(f"{p}\n")
    elif log == ".csv":
        with open(nomeFicheiro, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(p)

def sniffer(pkt, prtl, ip, mac, log, nomeFicheiro, capture_state, stop_capture, live, qnt=None) -> None:
    # processa um pacote recebido pelo callback do Scapy (prn)
    #data/hora do pacote
    tempo = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]

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

    # resumo do conteúdo
    info = conteudo_protocolo(pkt)

    if filtro(prtl, ip, mac, protocol, src_mac, dst_mac, src_ip, dst_ip):
        i = capture_state.get('i', 0)
        p, dados = printPacote(i, tempo, size, protocol, src_mac, dst_mac, src_ip, dst_ip, pkt, mac, info, live, qnt)
        if log == ".txt":
            logs(nomeFicheiro, p, log)
        elif log == ".csv" or log == ".json":
            logs(nomeFicheiro, dados, log)
        capture_state['i'] = i + 1


def ficheiro(log) -> str:
    tempo = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    nome = f"captura_{tempo}{log}"

    if log == ".txt":
        inicioT = f"----- Internet Packet Sniffer -----\n\n{'':<5}{'Tempo':<20} {'Origem':<20} {'Destino':<20} {'Protocolo':<10} {'Tamanho':<10} {'Info'}\n"
        with open(nome, 'w') as f:
            f.write(inicioT)

    elif log == ".csv":
        inicioC = ["Tempo", "Origem", "Destino", "Protocolo", "Tamanho", "Info"]
        with open(nome, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(inicioC)


    return nome

def main() -> int:
    args = parse()

    stop_capture = {"value": False}

    def tratar_sigint(_sig, _frame) -> None:
        stop_capture["value"] = True
        print("\nA parar captura...")

    signal.signal(signal.SIGINT, tratar_sigint)

    nomeFicheiro = ""
  
    if args.log is not None:
        if args.log not in [".txt", ".csv"]:
            raise ValueError("Uso inválido de --log. Usa .txt, ou .csv  | Use --help for more info")
        else :
            nomeFicheiro = ficheiro(args.log)

    i = 0

    if args.live:

        if not args.qnt:

            if args.log:

                print (f"\n--- [Modo ficheiro ativo] A guardar no ficheiro {nomeFicheiro} ... ---\n")

            print ("\n--- [Modo live ativo] Ctrl+C para sair ---\n")

            print(f"\n{"":<5}{"Tempo":<20} {"Origem":<20} {"Destino":<20} {"Protocolo":<10} {"Tamanho":<10} {"Info"}")
            capture_state = {'i': i}
            sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live, args.qnt), store=False, stop_filter=lambda x: stop_capture['value'], iface=args.iface if args.iface else None)
            i = capture_state.get('i', i)

        else:

            if args.log:

                print (f"\n--- [Modo ficheiro ativo] A guardar no ficheiro {nomeFicheiro} ... ---\n")

            print ("\n--- [Modo live ativo] ---\n")

            print (f"\n--- [Modo limitado ativo] Captura de {args.qnt} pacotes --- \n")

            print(f"\n{"":<5}{"Tempo":<20} {"Origem":<20} {"Destino":<20} {"Protocolo":<10} {"Tamanho":<10} {"Info"}")
            capture_state = {'i': i}
            has_filters = bool(args.prtl or args.ip or args.mac)
            if has_filters:
                sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live, args.qnt), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
            else:
                sniff(count=args.qnt, prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live, args.qnt), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
            i = capture_state.get('i', i)
            
        
    elif args.log and args.qnt:

        print (f"\n--- [Modo ficheiro ativo] A guardar no ficheiro {nomeFicheiro} ... ---\n")

        print (f"--- [Modo limitado ativo] Captura de {args.qnt} pacotes --- \n")
        capture_state = {'i': i}
        has_filters = bool(args.prtl or args.ip or args.mac)
        if has_filters:
            sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live, args.qnt), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
        else:
            sniff(count=args.qnt, prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live, args.qnt), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
        i = capture_state.get('i', i)

    elif args.log:

        print (f"\n--- [Modo ficheiro ativo] Ficheiro: {nomeFicheiro} ---\n")

        print (f"A guardar captura...\n")

        print (f"Prima Ctrl+C para sair \n")
        capture_state = {'i': i}
        sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live, args.qnt), store=False, stop_filter=lambda x: stop_capture['value'], iface=args.iface if args.iface else None)
        i = capture_state.get('i', i)


    print("\n--- [LarpSniffer] Programa Terminado! ---\n")
    return 0

if __name__ == "__main__":
    main()