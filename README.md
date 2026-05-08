# Sniffer_TP2RC

**Trabalho Prático  — RC**

Sniffer de pacotes em Python com análise de tráfego de rede e suporte a múltiplos protocolos.

## Descrição

Captura e análise de pacotes de rede usando Scapy. Detecta e formata resumos de protocolos comuns (ARP, DHCP, DNS, ICMP, TCP, UDP, IPv4, IPv6), regista em ficheiros de texto ou CSV, e identifica fragmentação IPv4.

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

### Filtros Disponíveis

- `--qnt` - Número de pacotes a capturar
- `--prtl` - Protocolo (ARP, DHCP, DNS, ICMP, TCP, UDP, HTTP, HTTPS, IPv4, IPv6, Ethernet)
- `--ip` - Filtrar por endereço IP (origem ou destino)
- `--mac` - Filtrar por endereço MAC (origem ou destino)
- `--iface` - Interface de rede
- `--log` - Tipo de ficheiro de saída (.txt ou .csv)
- `--live` - Modo captura contínua



### Captura (live)

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
### Filtrar por interface

```
sudo python3 main.py --iface eth0
sudo python3 main.py --iface wlp2s0 --qnt 50
sudo python3 main.py --iface eth0 --prtl DHCP --qnt 20 --log .csv
sudo python3 main.py --iface wlp2s0 --prtl ICMP --qnt 30 --log .txt
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

