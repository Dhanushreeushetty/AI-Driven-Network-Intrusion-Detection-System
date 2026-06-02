from scapy.all import rdpcap
from scapy.layers.inet import IP
from collections import defaultdict
import matplotlib.pyplot as plt

packets = rdpcap("port_scan_capture.pcap")

ip_count = defaultdict(int)

for packet in packets:
    if packet.haslayer(IP):
        src = packet[IP].src
        ip_count[src] += 1

print("\nPacket count per IP:\n")

for ip, count in ip_count.items():
    print(ip, "→", count)

print("\nPossible suspicious IPs:\n")

for ip, count in ip_count.items():
    if count > 10000:
        print("⚠ Suspicious traffic from:", ip, "| Packets:", count)
        
from scapy.layers.inet import TCP
from collections import defaultdict

port_scan = defaultdict(set)

for packet in packets:
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src = packet[IP].src
        port = packet[TCP].dport
        port_scan[src].add(port)

print("\nPossible Port Scanners:\n")

for ip, ports in port_scan.items():
    if len(ports) > 20:
        print("⚠ Possible Port Scan from:", ip, "| Ports scanned:", len(ports))        
        
from scapy.layers.inet import TCP, UDP
import pandas as pd

data = []

for packet in packets:
    if packet.haslayer(IP):
        src = packet[IP].src
        length = len(packet)

        port = None
        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport

        data.append([src, length, port])

df = pd.DataFrame(data, columns=["src_ip","length","port"])   

features = df.groupby("src_ip").agg({
    "length":"mean",
    "port":"nunique"
})

features["packet_count"] = df.groupby("src_ip").size()

print("\nTraffic Features:\n")
print(features)   

from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.1)

features["anomaly"] = model.fit_predict(features)

print("\nAI Detection Results:\n")
print(features)  

print("\nIntrusion Alerts:\n")

for ip, row in features.iterrows():
    if row["anomaly"] == -1:
        print("⚠ Possible intrusion detected from:", ip)
      
features.to_csv("network_features.csv")        



features["packet_count"].plot(kind="bar")
plt.title("Packet Count per IP")
plt.show()

features.to_csv("ids_results.csv", index=True)
print("IDS results saved to ids_results.csv")
