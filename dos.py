from scapy.all import *

for i in range(10000):
    send(IP(dst="127.0.0.1")/TCP(dport=80), verbose=0)