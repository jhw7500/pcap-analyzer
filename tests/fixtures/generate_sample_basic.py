"""기본 802.11 fixture pcap 생성 — 회귀 테스트용.

AP 1개(Beacon 2회) + STA 1개 + Auth/Assoc 시퀀스 + ICMP ping 2쌍.
실행:
    python3 /home/jhw/ai/opencode/projects/pcap-analyzer/tests/fixtures/generate_sample_basic.py
결과:
    sample_basic.pcap (작은 크기)
"""
from pathlib import Path

from scapy.all import (  # type: ignore
    RadioTap, Dot11, Dot11Beacon, Dot11Elt,
    LLC, SNAP, IP, ICMP, wrpcap,
)

AP_MAC = "00:11:22:33:44:55"
STA_MAC = "aa:bb:cc:dd:ee:ff"
BSSID = AP_MAC
SSID = "FixtureAP"

BASE_EPOCH = 1700000000.0  # 결정성 보장


def _stamp(pkt, epoch: float):
    pkt.time = epoch
    return pkt


def build():
    packets = []
    t = BASE_EPOCH

    # Beacon x2 (AP 식별)
    for i in range(2):
        beacon = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC, addr3=BSSID)
            / Dot11Beacon()
            / Dot11Elt(ID=0, info=SSID.encode())
        )
        packets.append(_stamp(beacon, t + i * 0.1))

    t += 0.5

    # Auth (STA → AP)
    auth1 = RadioTap() / Dot11(type=0, subtype=11, addr1=AP_MAC, addr2=STA_MAC, addr3=BSSID)
    packets.append(_stamp(auth1, t))
    # Auth response (AP → STA)
    auth2 = RadioTap() / Dot11(type=0, subtype=11, addr1=STA_MAC, addr2=AP_MAC, addr3=BSSID)
    packets.append(_stamp(auth2, t + 0.01))

    # AssocReq (STA → AP)
    assoc_req = RadioTap() / Dot11(type=0, subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=BSSID)
    packets.append(_stamp(assoc_req, t + 0.05))
    # AssocResp (AP → STA)
    assoc_resp = RadioTap() / Dot11(type=0, subtype=1, addr1=STA_MAC, addr2=AP_MAC, addr3=BSSID)
    packets.append(_stamp(assoc_resp, t + 0.06))

    t += 1.0

    # ICMP Ping 2 pairs (Request → Reply)
    for i in range(2):
        req = (
            RadioTap()
            / Dot11(type=2, subtype=0, addr1=AP_MAC, addr2=STA_MAC, addr3=BSSID)
            / LLC() / SNAP()
            / IP(src="192.168.1.100", dst="192.168.1.1")
            / ICMP(type=8, id=1, seq=i + 1)
        )
        packets.append(_stamp(req, t + i * 0.2))

        rep = (
            RadioTap()
            / Dot11(type=2, subtype=0, addr1=STA_MAC, addr2=AP_MAC, addr3=BSSID)
            / LLC() / SNAP()
            / IP(src="192.168.1.1", dst="192.168.1.100")
            / ICMP(type=0, id=1, seq=i + 1)
        )
        packets.append(_stamp(rep, t + i * 0.2 + 0.003))

    return packets


def main():
    out = Path(__file__).parent / "sample_basic.pcap"
    packets = build()
    wrpcap(str(out), packets)
    print(f"Wrote {out} ({out.stat().st_size} bytes, {len(packets)} packets)")


if __name__ == "__main__":
    main()
