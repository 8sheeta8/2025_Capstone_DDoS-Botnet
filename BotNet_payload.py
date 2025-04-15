from scapy.all import rdpcap, Raw, TCP, UDP, IP
from collections import defaultdict, Counter
import os, numpy as np

pcap_folder = "Botnet_pcap"  # 너의 PCAP 폴더
MAX_LEN = 500

payloads_by_type = defaultdict(list)

def auto_classify(pkt):
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport

        if sport == 6667 or dport == 6667:
            return "irc"
        if sport == 25 or dport == 25:
            return "spam"
        if dport in [135, 139, 445, 3389]:
            return "scan"
        if dport in [80, 443] or sport in [80, 443] or dport == 1072 or sport == 1072:
            return "fastflux"

    elif UDP in pkt:
        if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
            return "fastflux"

    return "unknown"


# 모든 pcap 파일 순회
for fname in os.listdir(pcap_folder):
    if not fname.endswith(".pcap"):
        continue

    fpath = os.path.join(pcap_folder, fname)
    try:
        packets = rdpcap(fpath)
    except Exception as e:
        print(f"❌ {fname} 로드 실패: {e}")
        continue

    for pkt in packets:
        if pkt.haslayer(Raw):
            attack_type = auto_classify(pkt)
            raw_bytes = bytes(pkt[Raw].load)
            seq = [int(b) for b in raw_bytes[:MAX_LEN]]
            seq += [0] * (MAX_LEN - len(seq))
            payloads_by_type[attack_type].append(seq)

save_dir = "botnet_payloads"
os.makedirs(save_dir, exist_ok=True)  # 폴더 없으면 자동 생성

for attack_type, data in payloads_by_type.items():
    npy_path = os.path.join(save_dir, f"{attack_type}_payloads.npy")
    np.save(npy_path, np.array(data))
    print(f"✅ {attack_type} 저장 완료: {npy_path} ({len(data)} samples)")
