# extract_ddos_payloads.py
from scapy.all import rdpcap, Raw, TCP, UDP, ICMP
from collections import defaultdict
import numpy as np
import os

# 설정
PCAP_PATH = "your_file.pcap"
MAX_LEN = 500
OUTPUT_DIR = "ddos_payloads"

# payload 저장 dict
payloads_by_type = defaultdict(list)

# pcap 읽기
packets = rdpcap(PCAP_PATH)

for pkt in packets:
    if not pkt.haslayer(Raw):
        continue
    raw = bytes(pkt[Raw].load)

    if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
        payloads_by_type["SYN_FLOOD"].append(raw)

    if pkt.haslayer(TCP) and pkt[TCP].dport in [80, 443]:
        if b"GET" in raw or b"POST" in raw or b"Host:" in raw:
            payloads_by_type["HTTP_FLOOD"].append(raw)

    if pkt.haslayer(ICMP):
        payloads_by_type["ICMP_FLOOD"].append(raw)

    if pkt.haslayer(UDP) and pkt[UDP].dport == 53:
        payloads_by_type["DNS_FLOOD"].append(raw)

    if pkt.haslayer(UDP):
        payloads_by_type["UDP_OTHER"].append(raw)

    if pkt.haslayer(TCP):
        payloads_by_type["TCP_OTHER"].append(raw)

# 저장 함수
def save_payloads_to_npy(payloads_by_type, output_dir=OUTPUT_DIR, max_len=MAX_LEN):
    os.makedirs(output_dir, exist_ok=True)
    for attack_type, payloads in payloads_by_type.items():
        sequences = []
        for p in payloads:
            seq = [int(b) for b in p[:max_len]]
            seq += [0] * (max_len - len(seq))
            sequences.append(seq)
        np.save(os.path.join(output_dir, attack_type.lower() + ".npy"), np.array(sequences))

# 실행
save_payloads_to_npy(payloads_by_type)
print("✅ 모든 공격 유형 payload 저장 완료")
