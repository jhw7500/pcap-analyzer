"""이중 무선 캡처 fixture 쌍 생성 — merge(TSF 오프셋·dedup) 골든 테스트용.

같은 AP를 두 곳(A/B)에서 동시에 캡처했다고 가정한다. A는 기준 시계(정확), B는
시계가 2.5초 느리다 — 같은 물리 프레임이 B에는 -2.5s 오프셋으로 찍힌다.

구성:
  - 공유 비콘 12개 — Dot11Beacon(timestamp=...)로 TSF를 직접 주입, A/B 양쪽에
    동일 (BSSID, TSF, seq) 프레임으로 기록되되 pcap 타임스탬프만 B가 2.5s 느림.
    비콘 간격은 실제 802.11 100 TU(102400µs)를 그대로 씀.
  - 공통 데이터 프레임 2개 (ICMP echo request/reply 쌍) — A는 복호화된 형태로
    LLC/SNAP/IP/ICMP까지 포함, B는 동일 wlan.seq의 802.11 Data이지만 payload가
    암호화된 것처럼 IP/ICMP를 포함하지 않는다 (실측 DFK 캡처가 완전 암호화인
    상황의 축소판 — analyzer/core/merge.py의 _prefer_new_representative 참고).
  - A 단독 프레임 1개, B 단독 프레임 1개 — coverage.only 검증용.

wlan.seq(Dot11.SC 필드)는 모든 프레임에 명시 설정한다 — TSF 폴백이 아니라도
merge.py의 dedup 키((TA, seq, subtype, retry))가 A/B의 "같은 물리 프레임"을
정확히 매칭하도록 하기 위함.

실행:
    python3 /home/jhw/ai/opencode/projects/pcap-analyzer/tests/fixtures/generate_sample_dual.py
결과:
    sample_dual_a.pcap, sample_dual_b.pcap (각각 작은 크기)
"""
from pathlib import Path

from scapy.all import (  # type: ignore
    RadioTap, Dot11, Dot11Beacon, Dot11Elt,
    LLC, SNAP, IP, ICMP, Raw, wrpcap,
)

AP_MAC = "00:11:22:33:44:55"
STA_MAC = "aa:bb:cc:dd:ee:ff"
BSSID = AP_MAC
SSID = "DualFixtureAP"

BASE_EPOCH = 1700000000.0  # 결정성 보장 — A(기준) 시계 기준 진짜 시각
TSF_START = 5_000_000      # µs, 임의 기준점(0 회피)
TSF_STRIDE = 102400        # µs — 802.11 기본 비콘 간격(100 TU)
NUM_BEACONS = 12
B_OFFSET = -2.5             # B의 pcap 타임스탬프 = 진짜 시각 + B_OFFSET (B 시계가 2.5s 느림)


def _stamp(pkt, epoch: float):
    pkt.time = epoch
    return pkt


def build():
    packets_a = []
    packets_b = []

    # 공유 비콘 12개 — 동일 (BSSID, TSF, seq), 캡처 타임스탬프만 다름
    for i in range(NUM_BEACONS):
        tsf = TSF_START + i * TSF_STRIDE
        seq = 1000 + i
        true_t = BASE_EPOCH + i * (TSF_STRIDE / 1e6)

        beacon_a = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2=AP_MAC, addr3=BSSID, SC=seq << 4)
            / Dot11Beacon(timestamp=tsf)
            / Dot11Elt(ID=0, info=SSID.encode())
        )
        packets_a.append(_stamp(beacon_a, true_t))

        beacon_b = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2=AP_MAC, addr3=BSSID, SC=seq << 4)
            / Dot11Beacon(timestamp=tsf)
            / Dot11Elt(ID=0, info=SSID.encode())
        )
        packets_b.append(_stamp(beacon_b, true_t + B_OFFSET))

    # 공통 데이터 프레임 2개 (ICMP echo request/reply) — A는 복호화(IP 포함),
    # B는 동일 wlan.seq의 802.11 Data이지만 IP/ICMP 없이 암호화된 것처럼 취급
    req_seq, rep_seq = 2000, 2001
    req_true_t = BASE_EPOCH + NUM_BEACONS * (TSF_STRIDE / 1e6) + 1.0
    rep_true_t = req_true_t + 0.003  # 3ms 후 응답 (sample_basic.py와 동일 관례)

    req_a = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=BSSID, SC=req_seq << 4)
        / LLC() / SNAP()
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / ICMP(type=8, id=1, seq=1)
    )
    packets_a.append(_stamp(req_a, req_true_t))

    req_b = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=BSSID,
                SC=req_seq << 4, FCfield="protected")
        / Raw(load=bytes(24))
    )
    packets_b.append(_stamp(req_b, req_true_t + B_OFFSET))

    rep_a = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=STA_MAC, addr2=AP_MAC, addr3=BSSID, SC=rep_seq << 4)
        / LLC() / SNAP()
        / IP(src="192.168.1.1", dst="192.168.1.100")
        / ICMP(type=0, id=1, seq=1)
    )
    packets_a.append(_stamp(rep_a, rep_true_t))

    rep_b = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=STA_MAC, addr2=AP_MAC, addr3=BSSID,
                SC=rep_seq << 4, FCfield="protected")
        / Raw(load=bytes(24))
    )
    packets_b.append(_stamp(rep_b, rep_true_t + B_OFFSET))

    # A 단독 프레임 1개 (B는 범위 밖이라 못 잡음)
    a_only_seq = 3000
    a_only_t = rep_true_t + 0.5
    a_only = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=BSSID, SC=a_only_seq << 4)
        / LLC() / SNAP()
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / ICMP(type=8, id=2, seq=1)
    )
    packets_a.append(_stamp(a_only, a_only_t))

    # B 단독 프레임 1개 (A는 범위 밖이라 못 잡음) — B 자신의 raw 시계 기준
    b_only_seq = 4000
    b_only_t = rep_true_t + 0.6 + B_OFFSET
    b_only = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=STA_MAC, addr2=AP_MAC, addr3=BSSID,
                SC=b_only_seq << 4, FCfield="protected")
        / Raw(load=bytes(24))
    )
    packets_b.append(_stamp(b_only, b_only_t))

    return packets_a, packets_b


def main():
    out_a = Path(__file__).parent / "sample_dual_a.pcap"
    out_b = Path(__file__).parent / "sample_dual_b.pcap"
    packets_a, packets_b = build()
    wrpcap(str(out_a), packets_a)
    wrpcap(str(out_b), packets_b)
    print(f"Wrote {out_a} ({out_a.stat().st_size} bytes, {len(packets_a)} packets)")
    print(f"Wrote {out_b} ({out_b.stat().st_size} bytes, {len(packets_b)} packets)")


if __name__ == "__main__":
    main()
