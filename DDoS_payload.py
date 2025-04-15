<<<<<<< HEAD
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
=======
from scapy.all import rdpcap, Raw, TCP, UDP, ICMP
from collections import defaultdict, Counter

# PCAP 파일 경로
pcap_path = "SAT-01-12-2018_0818"
packets = rdpcap(pcap_path)

# 공격 유형별 Payload 저장용
>>>>>>> bf5faf7 (BotNet_analyzer 코드(1))
payloads_by_type = defaultdict(list)

# pcap 읽기
packets = rdpcap(PCAP_PATH)

for pkt in packets:
    if not pkt.haslayer(Raw):
<<<<<<< HEAD
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
=======
        continue  # Raw payload 없으면 무시

    raw = bytes(pkt[Raw].load)

    # --- SYN 플러딩 계열 ---
    if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:  # SYN 포함
        payloads_by_type["SYN_FLOOD"].append(raw)

    # --- ACK Flood / TCP ACK 대량 트래픽 ---
    if pkt.haslayer(TCP) and pkt[TCP].flags & 0x10:  # ACK 포함
        payloads_by_type["TCP_ACK"].append(raw)

    # --- HTTP Flood ---
    if pkt.haslayer(TCP) and pkt[TCP].dport in [80, 443]:
        if b"GET" in raw or b"POST" in raw or b"Host:" in raw:
            payloads_by_type["HTTP_FLOOD"].append(raw)

    # --- DNS Flood ---
    if pkt.haslayer(UDP) and pkt[UDP].dport == 53:
        payloads_by_type["DNS_FLOOD"].append(raw)

    # --- ICMP Flood ---
    if pkt.haslayer(ICMP):
        payloads_by_type["ICMP_FLOOD"].append(raw)

    # --- SSDP / NTP / 기타 반사형 ---
    if pkt.haslayer(UDP) and pkt[UDP].sport in [123, 1900, 19]:  # NTP, SSDP, Chargen
        payloads_by_type["UDP_REFLECTION"].append(raw)

    # --- 미확인 but Raw가 있는 UDP ---
    if pkt.haslayer(UDP):
        payloads_by_type["UDP_OTHER"].append(raw)

    # --- 기타 모든 TCP 트래픽 중 Raw가 있는 것 ---
    if pkt.haslayer(TCP):
        payloads_by_type["TCP_OTHER"].append(raw)

# 결과 요약 출력
for attack_type, payloads in payloads_by_type.items():
    counter = Counter(payloads)
    print(f"\n📌 {attack_type} — 상위 3개 Payload:")
    for i, (payload, count) in enumerate(counter.most_common(3)):
        print(f"{i+1}. Count={count}, Payload={payload[:60]}")

import numpy as np
import os

# 저장할 최대 길이
MAX_LEN = 500

def save_payloads_to_npy(payloads_by_type, output_dir="ddos_payloads", max_len=MAX_LEN):
    os.makedirs(output_dir, exist_ok=True)

    for attack_type, payloads in payloads_by_type.items():
        sequences = []

>>>>>>> bf5faf7 (BotNet_analyzer 코드(1))
        for p in payloads:
            seq = [int(b) for b in p[:max_len]]
            seq += [0] * (max_len - len(seq))
            sequences.append(seq)
<<<<<<< HEAD
        np.save(os.path.join(output_dir, attack_type.lower() + ".npy"), np.array(sequences))

# 실행
save_payloads_to_npy(payloads_by_type)
print("✅ 모든 공격 유형 payload 저장 완료")
=======

        # numpy 배열로 변환
        X = np.array(sequences)

        # 공격 유형 이름 소문자 처리
        attack_file = attack_type.lower().replace(" ", "_") + ".npy"
        path = os.path.join(output_dir, attack_file)

        # 저장
        np.save(path, X)
        print(f"✅ 저장 완료: {path} ({X.shape[0]} sequences)")


# 실행
save_payloads_to_npy(payloads_by_type)
print("✅ 모든 공격 유형 payload 저장 완료")
>>>>>>> bf5faf7 (BotNet_analyzer 코드(1))
