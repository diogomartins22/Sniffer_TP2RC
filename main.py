"""Sniffer de pacotes em modo CLI com Scapy."""
from __future__ import annotations
import argparse
import signal
from datetime import datetime
from scapy.all import sniff, Ether, IP, ARP, ICMP, TCP, UDP, DNS, DHCP, BOOTP
import csv

def detetar_protocolo(pct) -> str:
    # Identifica o tipo de protocolo do pacote (ARP, DHCP, DNS, ICMP, TCP, UDP, IPv4, etc).
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
        except (ValueError, TypeError, AttributeError):
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
    # Gera um resumo legível dos detalhes do protocolo para a coluna Info.
    if pct.haslayer(ARP):
        # ARP: distinguir request (op=1) e reply (op=2).
        if pct[ARP].op == 1:
            return "ARP request"
        elif pct[ARP].op == 2:
            return "ARP reply"

    if pct.haslayer(DHCP):
        # Extrai opções DHCP e mostra campos relevantes (tipo, IP, máscara, etc).
        dhcp_opts = pct[DHCP].options
        opts = {}
        for opt in dhcp_opts:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opts[opt[0]] = opt[1]

        # Mapeia message-type (1=Discover, 2=Offer, 3=Request, etc).
        mt = opts.get('message-type')
        try:
            if isinstance(mt, (bytes, bytearray)) and len(mt) >= 1:
                mtv = mt[0]
            else:
                mtv = int(mt) if mt is not None else None
        except Exception:
            mtv = None
        mapping = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'Ack', 6: 'Nak', 7: 'Release', 8: 'Inform'}
        mname = mapping.get(mtv, None) if mtv is not None else None

        ch = None
        if pct.haslayer(BOOTP):
            raw_ch = getattr(pct[BOOTP], 'chaddr', None)
            if isinstance(raw_ch, (bytes, bytearray)):
                ch = ':'.join(f"{b:02x}" for b in raw_ch[:6])
            else:
                ch = raw_ch

        parts = []
        if mname:
            parts.append(f"DHCP {mname}")
        else:
            parts.append("DHCP")

        # selected short fields only
        if 'requested_addr' in opts:
            parts.append(f"req={opts['requested_addr']}")
        if 'server_id' in opts:
            parts.append(f"svr={opts['server_id']}")
        if 'lease_time' in opts:
            parts.append(f"lease={opts['lease_time']}")
        if 'subnet_mask' in opts:
            parts.append(f"mask={opts['subnet_mask']}")
        if ch:
            parts.append(f"ch={ch}")

        return '   '.join(parts)
        
    if pct.haslayer(DNS):
        # DNS: qr=0 é query, qr=1 é response.
        if getattr(pct[DNS], 'qr', 0) == 0:
            qr = "DNS query"
        else:
            qr = "DNS response"
        return f"{qr}   id = {getattr(pct[DNS], 'id', '?')}  qdCount = {getattr(pct[DNS], 'qdcount', '?')}  anCount = {getattr(pct[DNS], 'ancount', '?')}"
    
    if pct.haslayer(ICMP):
        # ICMP: echo request (type=8) e reply (type=0); campos id/seq existem só para echo.
        icmp_type = getattr(pct[ICMP], 'type', None)
        if icmp_type == 8:
            tipo = "ICMP echo request"
        elif icmp_type == 0:
            tipo = "ICMP echo reply"
        else:
            tipo = f"ICMP type={icmp_type}"
        code = getattr(pct[ICMP], 'code', None)
        chksum = getattr(pct[ICMP], 'chksum', None)
        parts = [f"{tipo}"]
        if code is not None:
            parts.append(f"Code={code}")
        # id/seq only meaningful for echo messages
        if icmp_type in (0, 8):
            iid = getattr(pct[ICMP], 'id', None)
            seq = getattr(pct[ICMP], 'seq', None)
            if iid is not None:
                parts.append(f"Id={iid}")
            if seq is not None:
                parts.append(f"Seq={seq}")
        if chksum is not None:
            parts.append(f"Checksum={chksum}")
        return '   '.join(parts)
        
    if pct.haslayer(TCP):
        # TCP: mostra flags (SYN, ACK, FIN, etc) e campos seq/ack/window/checksum.
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
        # UDP: comprimento do datagrama e checksum.
        return f"Length = {pct[UDP].len}  Checksum = {pct[UDP].chksum}"

    if pct.haslayer(IP):
        # IPv4: TTL, flags, tamanho total e checksum.
        flag = pct[IP].flags
        if not flag :
            flag = "0"
        return f"TTL = {pct[IP].ttl}  Flag = {flag}  Len = {pct[IP].len}  Checksum = {pct[IP].chksum}"
    
    return ""

def parse():
    # Processa argumentos de linha de comandos (qnt, prtl, ip, mac, log, iface, live).
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

    # Default behaviour: if user didn't request non-live capture options, run live
    if not args.live:
        if args.qnt is None and args.log is None:
            args.live = True

    return args

def printPacote(i, tempo, size, protocol, src_mac, dst_mac, src_ip, dst_ip, pkt, mac, info, live) -> str:
    # Formata uma linha de pacote para exibição (prioridade: MAC se --mac, senão IP).
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
    # Verifica se o pacote passa nos critérios de filtro (protocolo, IP, MAC).
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
    # Regista um pacote num ficheiro .txt (linha) ou .csv (linha estruturada).
    if log == ".txt":
        with open(nomeFicheiro, 'a') as f:
            f.write(f"{p}\n")
    elif log == ".csv":
        with open(nomeFicheiro, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(p)

def sniffer(pkt, prtl, ip, mac, log, nomeFicheiro, capture_state, stop_capture, live) -> None:
    # Callback do Scapy para processar cada pacote: extrai campos, detecta fragments, filtra, regista.
    # Calcula timestamp, tamanho, protocolo e endereços.
    tempo = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]

    size = len(pkt)
    protocol = detetar_protocolo(pkt)
    src_mac = pkt[Ether].src if Ether in pkt else "?"
    dst_mac = pkt[Ether].dst if Ether in pkt else "?"
    src_ip = pkt[IP].src if IP in pkt else "?"
    dst_ip = pkt[IP].dst if IP in pkt else "?"

    info = conteudo_protocolo(pkt)

    # Detecta fragments IPv4 (offset != 0 ou MF=1) e agrupa-os por (src,dst,proto,id).
    if IP in pkt:
        try:
            frag_offset = int(pkt[IP].frag)
        except (ValueError, TypeError, AttributeError):
            frag_offset = 0

        mf = False
        # Testa bit MF (0x20) da flag de fragmentação.
        try:
            flags = pkt[IP].flags
            mf = bool(getattr(flags, 'MF', False) or (int(flags) & 0x20))
        except Exception:
            mf = False

        if frag_offset != 0 or mf:
            frags = capture_state.get('frags')
            if frags is None:
                frags = {}
                capture_state['frags'] = frags

            key = (pkt[IP].src, pkt[IP].dst, getattr(pkt[IP], 'proto', '?'), getattr(pkt[IP], 'id', '?'))
            lst = frags.get(key)
            if lst is None:
                lst = []
                frags[key] = lst

            # Usa o próximo índice para agrupar fragments.
            cur_idx = capture_state.get('i', 0) + 1
            if cur_idx not in lst:
                lst.append(cur_idx)

            frag_summary = f"FRAG id={key[3]} off={frag_offset} MF={1 if mf else 0} parts={','.join(str(x) for x in lst)}"
            info = f"{info}   | {frag_summary}" if info else frag_summary

    # Aplica filtros; se não passar, ignora o pacote.
    if not filtro(prtl, ip, mac, protocol, src_mac, dst_mac, src_ip, dst_ip):
        return

    # Imprime e regista o pacote.
    i = capture_state.get('i', 0)
    p, dados = printPacote(i, tempo, size, protocol, src_mac, dst_mac, src_ip, dst_ip, pkt, mac, info, live)
    if log == ".txt":
        logs(nomeFicheiro, p, log)
    elif log == ".csv":
        logs(nomeFicheiro, dados, log)
    capture_state['i'] = i + 1


def ficheiro(log) -> str:
    # Cria ficheiro de saída com cabeçalho (texto ou CSV).
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
    # Captura de pacotes: processa argumentos, cria ficheiro, executa sniff.
    args = parse()

    stop_capture = {"value": False}

    def tratar_sigint(_sig, _frame) -> None:
        stop_capture["value"] = True
        print("\nA parar captura...")
        # Interrompe imediatamente o sniff, mesmo sem chegada de novos pacotes.
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, tratar_sigint)

    nomeFicheiro = ""
  
    if args.log is not None:
        if args.log not in [".txt", ".csv"]:
            raise ValueError("Uso inválido de --log. Usa .txt, ou .csv  | Use --help for more info")
        else :
            nomeFicheiro = ficheiro(args.log)

    i = 0

    try:
        if args.live:

            if not args.qnt:

                if args.log:

                    print (f"\n--- [Modo ficheiro ativo] A guardar no ficheiro {nomeFicheiro} ... ---\n")

                print ("\n--- [Modo live ativo] Ctrl+C para sair ---\n")

                print(f"\n{'':<5}{'Tempo':<20} {'Origem':<20} {'Destino':<20} {'Protocolo':<10} {'Tamanho':<10} {'Info'}")
                capture_state = {'i': i}
                sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live), store=False, stop_filter=lambda x: stop_capture['value'], iface=args.iface if args.iface else None)
                i = capture_state.get('i', i)

            else:

                if args.log:

                    print (f"\n--- [Modo ficheiro ativo] A guardar no ficheiro {nomeFicheiro} ... ---\n")

                print ("\n--- [Modo live ativo] ---\n")

                print (f"\n--- [Modo limitado ativo] Captura de {args.qnt} pacotes --- \n")

                print(f"\n{'':<5}{'Tempo':<20} {'Origem':<20} {'Destino':<20} {'Protocolo':<10} {'Tamanho':<10} {'Info'}")
                capture_state = {'i': i}
                has_filters = bool(args.prtl or args.ip or args.mac)
                if has_filters:
                    sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
                else:
                    sniff(count=args.qnt, prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
                i = capture_state.get('i', i)
            
        
        elif args.log and args.qnt:

            print (f"\n--- [Modo ficheiro ativo] A guardar no ficheiro {nomeFicheiro} ... ---\n")

            print (f"--- [Modo limitado ativo] Captura de {args.qnt} pacotes --- \n")
            capture_state = {'i': i}
            has_filters = bool(args.prtl or args.ip or args.mac)
            if has_filters:
                sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
            else:
                sniff(count=args.qnt, prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live), store=False, stop_filter=lambda x: stop_capture['value'] or capture_state.get('i', 0) >= args.qnt, iface=args.iface if args.iface else None)
            i = capture_state.get('i', i)

        elif args.log:

            print (f"\n--- [Modo ficheiro ativo] Ficheiro: {nomeFicheiro} ---\n")

            print (f"A guardar captura...\n")

            print (f"Prima Ctrl+C para sair \n")
            capture_state = {'i': i}
            sniff(prn=lambda pkt: sniffer(pkt, args.prtl, args.ip, args.mac, args.log, nomeFicheiro, capture_state, stop_capture, args.live), store=False, stop_filter=lambda x: stop_capture['value'], iface=args.iface if args.iface else None)
            i = capture_state.get('i', i)
    except KeyboardInterrupt:
        pass


    print("\n--- [LarpSniffer] Programa Terminado! ---\n")
    return 0

if __name__ == "__main__":
    main()