from scapy.all import sniff, IP
from collections import defaultdict
import os
import threading
import time

t = defaultdict(int)

def private(ip):
    return ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))

def pkt(p):
    if IP in p:
        ip = p[IP].dst
        if not private(ip):
            t[ip] += len(p)

def draw():
    while True:
        os.system("cls")
        print("blvcksyxx sniffer [v1]\n")

        top = sorted(t.items(), key=lambda x: x[1], reverse=True)[:10]

        for i, (ip, v) in enumerate(top):
            print(f"{i}. {ip} > {v/1024:.2f} kb")

        time.sleep(1)

threading.Thread(target=draw, daemon=True).start()
sniff(prn=pkt, store=0)