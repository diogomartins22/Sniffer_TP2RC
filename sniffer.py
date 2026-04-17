import sys
from scapy.all import sniff

packets = sniff(count=10)

packets.summary()