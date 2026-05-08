"""pcap 프레임에서 AP/STA MAC 역할을 자동 감지한다."""
from typing import Dict, List
from collections import Counter
from .models import Frame

BROADCAST = "ff:ff:ff:ff:ff:ff"
MULTICAST_PREFIXES = ("33:33:", "01:00:5e:", "01:80:c2:")
AP_SUBTYPES = {"5", "8"}  # ProbeResp, Beacon


def _is_unicast(mac: str) -> bool:
    """유니캐스트 MAC인지 확인. 멀티캐스트/브로드캐스트 제외."""
    if not mac or mac == BROADCAST:
        return False
    if mac.startswith(MULTICAST_PREFIXES):
        return False
    # MAC 첫 옥텟의 LSB가 1이면 멀티캐스트
    try:
        first_octet = int(mac[:2], 16)
        if first_octet & 0x01:
            return False
    except ValueError:
        return False
    return True


def detect_roles(frames: List[Frame]) -> Dict[str, Dict]:
    mac_counts = Counter()
    ap_macs = set()

    for f in frames:
        if _is_unicast(f.ta):
            mac_counts[f.ta] += 1
        if _is_unicast(f.ra):
            mac_counts[f.ra] += 1
        if f.subtype in AP_SUBTYPES and _is_unicast(f.ta):
            ap_macs.add(f.ta)

    # AssocResp / ReassocResp 를 보내는 MAC도 AP
    for f in frames:
        if f.subtype in ("1", "3") and _is_unicast(f.ta):
            ap_macs.add(f.ta)

    # BSSID 기반 STA 판별:
    # 1단계: Data 프레임에서 AP와 실제 통신한 MAC만 STA 후보로 수집
    #   - Probe Response 대상(지나가는 단말)이 제외됨
    # 2단계: STA 후보의 전체 프레임 수를 카운트
    # 폴백: beacon/assoc 없는 캡처에서 ap_macs가 비어있으면 bssid 필터 스킵
    sta_candidates = set()
    for f in frames:
        if ap_macs and f.bssid not in ap_macs:
            continue
        if not f.is_data:
            continue
        if _is_unicast(f.ta) and f.ta not in ap_macs:
            sta_candidates.add(f.ta)
        if _is_unicast(f.ra) and f.ra not in ap_macs:
            sta_candidates.add(f.ra)

    sta_counts = Counter()
    for f in frames:
        if f.ta in sta_candidates:
            sta_counts[f.ta] += 1
        if f.ra in sta_candidates:
            sta_counts[f.ra] += 1

    roles = {}
    ap_idx = 1
    sta_idx = 1

    for mac in sorted(ap_macs, key=lambda m: mac_counts.get(m, 0), reverse=True):
        short = mac[-8:].replace(":", "")  # 마지막 3바이트 (6hex)
        roles[mac] = {"role": "AP", "name": f"AP{ap_idx}({short})", "count": mac_counts[mac]}
        ap_idx += 1

    for mac in sorted(sta_counts, key=lambda m: sta_counts[m], reverse=True):
        if mac in roles or mac == BROADCAST:
            continue
        if sta_counts[mac] < 5:
            continue
        short = mac[-8:].replace(":", "")  # 마지막 3바이트 (6hex)
        roles[mac] = {"role": "STA", "name": f"STA{sta_idx}({short})", "count": sta_counts[mac]}
        sta_idx += 1

    return roles


def mac_name(mac: str, roles: Dict[str, Dict]) -> str:
    if mac == BROADCAST:
        return "BCAST"
    if mac in roles:
        return roles[mac]["name"]
    return mac[-5:] if mac else "?"
