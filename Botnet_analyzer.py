import os
from scapy.all import rdpcap, TCP, UDP, ICMP, IP
from collections import Counter

# 분석할 폴더 경로
pcap_folder = "Botnet_pcap"

# 폴더 내 모든 pcap 파일 분석
for fname in os.listdir(pcap_folder):
    if not fname.endswith(".pcap"):
        continue

    pcap_path = os.path.join(pcap_folder, fname)
    print(f"\n📁 파일 분석 중: {fname}")
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"❌ {fname} 로딩 실패: {e}")
        continue

    # 카운터 초기화
    proto_counter = Counter()
    tcp_flag_counter = Counter()
    sport_counter = Counter()
    dport_counter = Counter()
    ip_counter = Counter()

    for pkt in packets:
        if IP in pkt:
            proto_counter[pkt[IP].proto] += 1
            ip_counter[pkt[IP].dst] += 1

        if TCP in pkt:
            tcp_flag_counter[pkt[TCP].flags] += 1
            sport_counter[pkt[TCP].sport] += 1
            dport_counter[pkt[TCP].dport] += 1

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
    print("--------------------------------------------------")