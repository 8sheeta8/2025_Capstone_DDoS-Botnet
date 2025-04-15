from scapy.all import rdpcap, TCP, UDP, ICMP, Raw
from collections import defaultdict, Counter

pcap_path = "SAT-01-12-2018_0818"
packets = rdpcap(pcap_path)

payloads_by_type = defaultdict(list)

for pkt in packets:
    # SYN Flood
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        if pkt.haslayer(Raw):
            payloads_by_type["SYN_FLOOD"].append(bytes(pkt[Raw].load))

    # HTTP Flood
    elif pkt.haslayer(TCP) and pkt[TCP].dport in [80, 443]:
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            if b"GET" in raw or b"POST" in raw:
                payloads_by_type["HTTP_FLOOD"].append(raw)

    # DNS Flood
    elif pkt.haslayer(UDP) and pkt[UDP].dport == 53:
        if pkt.haslayer(Raw):
            payloads_by_type["DNS_FLOOD"].append(bytes(pkt[Raw].load))

    # ICMP Flood
    elif pkt.haslayer(ICMP):
        if pkt.haslayer(Raw):
            payloads_by_type["ICMP_FLOOD"].append(bytes(pkt[Raw].load))

# 상위 Payload 출력
for attack_type, payloads in payloads_by_type.items():
    counter = Counter(payloads)
    print(f"\n📌 {attack_type} — 상위 3개 Payload:")
    for i, (payload, count) in enumerate(counter.most_common(3)):
        print(f"{i+1}. Count={count}, Payload={payload[:60]}")
