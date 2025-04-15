from scapy.all import rdpcap, TCP, UDP, ICMP, IP
from collections import Counter

pcap_path = "SAT-01-12-2018_0818"
packets = rdpcap(pcap_path)

ip_counter = Counter()
proto_counter = Counter()
sport_counter = Counter()
dport_counter = Counter()
tcp_flag_counter = Counter()

for pkt in packets:
    if IP in pkt:
        ip_counter[pkt[IP].dst] += 1
        proto = pkt[IP].proto
        proto_counter[proto] += 1

    if TCP in pkt:
        sport_counter[pkt[TCP].sport] += 1
        dport_counter[pkt[TCP].dport] += 1
        tcp_flag_counter[pkt[TCP].flags] += 1

    elif UDP in pkt:
        sport_counter[pkt[UDP].sport] += 1
        dport_counter[pkt[UDP].dport] += 1

    elif ICMP in pkt:
        proto_counter["ICMP"] += 1

# 결과 출력
print("📌 프로토콜 분포:", proto_counter)
print("📌 TCP flags 분포:", tcp_flag_counter)
print("📌 목적지 포트 상위 10개:", dport_counter.most_common(10))
print("📌 목적지 IP 상위 10개:", ip_counter.most_common(10))
