"""RSSI 급변(cliff) 탐지 + 이동 평균."""
from typing import Any, Dict, List


def analyze_signal_cliffs(signal_data: Dict[str, Any]) -> Dict[str, Any]:
    """STA별 RSSI cliff 이벤트와 이동 평균을 계산한다."""
    result = {}
    for sta_name, sta_info in signal_data.get("stas", {}).items():
        timeline = sta_info.get("rssi_timeline", [])
        if len(timeline) < 10:
            result[sta_name] = {"cliffs": [], "moving_avg": []}
            continue

        # 이동 평균 (window=20)
        window = 20
        moving_avg = []
        for i in range(len(timeline)):
            start = max(0, i - window)
            chunk = [p["rssi"] for p in timeline[start:i+1] if p.get("rssi") is not None]
            if chunk:
                moving_avg.append({"epoch": timeline[i]["epoch"], "rssi": sum(chunk) / len(chunk)})

        # Cliff 탐지: 5초 내 10dBm 이상 하락
        cliffs = []
        i = 0
        while i < len(timeline):
            rssi_i = timeline[i].get("rssi")
            if rssi_i is None:
                i += 1
                continue
            j = i + 1
            while j < len(timeline) and timeline[j]["epoch"] - timeline[i]["epoch"] <= 5.0:
                rssi_j = timeline[j].get("rssi")
                if rssi_j is not None and rssi_i - rssi_j >= 10:
                    cliffs.append({
                        "epoch": timeline[i]["epoch"],
                        "rssi_before": rssi_i,
                        "rssi_after": rssi_j,
                        "drop_db": rssi_i - rssi_j,
                        "duration_sec": round(timeline[j]["epoch"] - timeline[i]["epoch"], 2),
                    })
                    i = j  # skip ahead
                    break
                j += 1
            i += 1

        result[sta_name] = {"cliffs": cliffs, "moving_avg": moving_avg}

    return result
