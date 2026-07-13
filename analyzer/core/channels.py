"""채널 주파수(MHz) → 채널 번호/밴드 변환 유틸.

radiotap.channel.freq 값(예: "5240")을 802.11 채널 번호와 밴드(2.4/5/6GHz)로
변환한다. 소비자: analyzer/web/structured.py(overview.channels, roaming
band_change), report.py, prompts.py.
"""
from typing import Any, Dict, List, Optional


def parse_freq(raw: str) -> Optional[int]:
    """tshark 필드 문자열 → 주파수 MHz 정수. multi-value는 첫 값. 실패 시 None."""
    if not raw:
        return None
    first = str(raw).split(",")[0].strip()
    if not first:
        return None
    try:
        return int(float(first))
    except (ValueError, TypeError):
        return None


def freq_to_channel(freq_mhz: Optional[int]) -> Optional[int]:
    """주파수 MHz → 802.11 채널 번호. 알 수 없는 대역은 None."""
    if freq_mhz is None:
        return None
    # 2.4GHz: ch1~13 = 2412~2472 (5MHz 간격), ch14 = 2484 (일본 특례)
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 2484:
        return 14
    # 5GHz: ch = (freq - 5000) / 5 (5160~5885)
    if 5150 <= freq_mhz <= 5895:
        return (freq_mhz - 5000) // 5
    # 6GHz: ch2 = 5935 특례, 그 외 ch = (freq - 5950) / 5 (5955~7115)
    if freq_mhz == 5935:
        return 2
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    return None


def freq_to_band(freq_mhz: Optional[int]) -> Optional[str]:
    """주파수 MHz → 밴드 문자열("2.4GHz"|"5GHz"|"6GHz"). 알 수 없으면 None."""
    if freq_mhz is None:
        return None
    if 2400 <= freq_mhz <= 2500:
        return "2.4GHz"
    if 5150 <= freq_mhz <= 5895:
        return "5GHz"
    if freq_mhz == 5935 or 5955 <= freq_mhz <= 7115:
        return "6GHz"
    return None


def channel_info(raw_freq: str) -> Optional[Dict[str, Any]]:
    """Frame.channel_freq 문자열 → {"freq", "channel", "band"} dict. 실패 시 None."""
    freq = parse_freq(raw_freq)
    if freq is None:
        return None
    return {
        "freq": freq,
        "channel": freq_to_channel(freq),
        "band": freq_to_band(freq),
    }


def ap_channel_map(frames: List, roles: Dict[str, Dict]) -> Dict[str, Dict[str, Any]]:
    """AP MAC → 대표 채널 정보. AP가 송신한 beacon(subtype 8)의 최빈 주파수 기준.

    beacon이 없는 AP는 맵에서 빠진다(채널 정보 없음 → 소비자는 .get()으로 분기).
    """
    from collections import Counter

    ap_macs = {mac for mac, info in roles.items() if info.get("role") == "AP"}
    freq_counts: Dict[str, "Counter[int]"] = {}
    for f in frames:
        if f.subtype != "8" or f.ta not in ap_macs:
            continue
        freq = parse_freq(getattr(f, "channel_freq", "") or "")
        if freq is None:
            continue
        freq_counts.setdefault(f.ta, Counter())[freq] += 1

    result: Dict[str, Dict[str, Any]] = {}
    for mac, ctr in freq_counts.items():
        freq = ctr.most_common(1)[0][0]
        result[mac] = {
            "freq": freq,
            "channel": freq_to_channel(freq),
            "band": freq_to_band(freq),
        }
    return result
