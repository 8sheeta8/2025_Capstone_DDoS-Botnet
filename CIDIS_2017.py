import os
from scapy.all import rdpcap, wrpcap, IP

# ✅ 입력 PCAP 파일
input_pcap = "Friday-WorkingHours.pcap"

# ✅ Botnet 정보
botnet_output_dir = "Botnet"
botnet_output_pcap = os.path.join(botnet_output_dir, "Botnet_only_packets.pcap")
bot_ips = {
    "192.168.10.15", "192.168.10.9",
    "192.168.10.14", "192.168.10.5", "192.168.10.8"
}
bot_start = 1499418120  # 2017-07-07 10:02:00 UTC
bot_end = 1499421720    # 2017-07-07 11:02:00 UTC

# ✅ LOIC 정보
loic_output_dir = "LOIC"
loic_output_pcap = os.path.join(loic_output_dir, "LOIC_only_packets.pcap")
loic_attackers = {"205.174.165.69", "205.174.165.70", "205.174.165.71"}
loic_start = 1499458560  # 2017-07-07 15:56:00 UTC
loic_end = 1499459776    # 2017-07-07 16:16:00 UTC

# ✅ 출력 폴더 생성
os.makedirs(botnet_output_dir, exist_ok=True)
os.makedirs(loic_output_dir, exist_ok=True)

# ✅ PCAP 읽기
print("📥 PCAP 파일 로딩 중...")
packets = rdpcap(input_pcap)

# ✅ Botnet 패킷 필터링
print("🔍 Botnet 패킷 필터링 중...")
botnet_packets = [
    pkt for pkt in packets
    if IP in pkt and
    (pkt[IP].src in bot_ips or pkt[IP].dst in bot_ips) and
    bot_start <= pkt.time <= bot_end
]

# ✅ LOIC 패킷 필터링
print("🔍 LOIC 패킷 필터링 중...")
loic_packets = [
    pkt for pkt in packets
    if IP in pkt and
    pkt[IP].src in loic_attackers and
    loic_start <= pkt.time <= loic_end
]

# ✅ 결과 저장
wrpcap(botnet_output_pcap, botnet_packets)
wrpcap(loic_output_pcap, loic_packets)

# ✅ 결과 출력
print(f"✅ Botnet 패킷 {len(botnet_packets)}개 저장됨 → '{botnet_output_pcap}'")
print(f"✅ LOIC 패킷 {len(loic_packets)}개 저장됨 → '{loic_output_pcap}'")
