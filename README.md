# Sniffer_TP2RC

**Trabalho Prático  — RC**

Sniffer de pacotes em Python com análise de tráfego de rede e suporte a múltiplos protocolos.

## Descrição

CLI de captura e análise de pacotes de rede usando Scapy. Detecta e formata resumos de protocolos comuns (ARP, DHCP, DNS, ICMP, TCP, UDP, IPv4), regista em ficheiros de texto ou CSV, e identifica fragmentação IPv4.

### Características

- **Captura em tempo real** com callback Scapy (sem perda de pacotes)
- **Múltiplos protocolos**: ARP, DHCP, DNS, ICMP, TCP, UDP, IPv4, HTTP, HTTPS
- **Filtros**: por protocolo, IP (src/dst), MAC (src/dst)
- **Saída**: texto (.txt) ou CSV (.csv) com campos estruturados
- **Interface flexível**: captura contínua (live), limitada (--qnt) ou combinada com ficheiro
- **Suporte a interfaces múltiplas**: especificar com --iface

## Dependências

```
- python3
- argparse                      # Processamento de argumentos CLI
- signal                        # Captura de sinais (Ctrl+C)
- datetime                      # Timestamps e formatação de datas
- scapy                         # Captura e análise de pacote
- csv                           # Escrita de ficheiros CSV
```


## Uso

### Captura contínua (live)

```
sudo python3 main.py
```

### Captura N pacotes

```
sudo python3 main.py --qnt 100
```

### Gravar em ficheiro

```
sudo python3 main.py --qnt 100 --log .txt    # texto legível
sudo python3 main.py --qnt 100 --log .csv    # CSV estruturado
```

### Filtrar por protocolo

```
sudo python3 main.py --prtl DNS --qnt 50 --log .txt
sudo python3 main.py --prtl DHCP --qnt 20 --log .csv
sudo python3 main.py --prtl ICMP --qnt 30
```

### Filtrar por IP

```
sudo python3 main.py --ip 192.168.1.1 src --qnt 50     # origem
sudo python3 main.py --ip 8.8.8.8 dst --qnt 50          # destino
```

### Filtrar por MAC

```
sudo python3 main.py --mac aa:bb:cc:dd:ee:ff src --qnt 50
```

### Exemplos de comandos para correr

```
sudo python3 main.py --qnt 100 --iface eth0 --log .txt
sudo python3 main.py --qnt 100 --iface wlp2s0 --log .csv
```

### Ajuda

```
sudo python3 main.py --help
```



## Notas Importantes

1. **Permissões**: A captura de pacotes requer privilégios de administrador/root.

