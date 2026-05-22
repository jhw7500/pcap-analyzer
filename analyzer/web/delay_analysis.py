"""통신 지연 패턴 분석 모듈 — ping RTT/loss 데이터에서 지연 구간을 탐지한다."""
import math
from typing import Any, Dict, List


def _moving_avg_std(values: List[float], window: int = 10):
    """이동 평균과 표준편차를 계산한다. 각 인덱스마다 (avg, std) 튜플 리스트 반환."""
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        chunk = values[start:i + 1]
        avg = sum(chunk) / len(chunk)
        if len(chunk) > 1:
            var = sum((v - avg) ** 2 for v in chunk) / (len(chunk) - 1)
            std = math.sqrt(var)
        else:
            std = 0.0
        result.append((avg, std))
    return result


def _find_cause(
    start_epoch: float,
    end_epoch: float,
    roaming_sequences: List[Dict],
    per_second_timeline: List[Dict],
) -> str:
    """지연 구간의 원인을 추정한다."""
    # 로밍 이벤트가 2초 이내에 있는지 확인
    for seq in roaming_sequences:
        roam_epoch = seq.get("auth_epoch", 0)
        if abs(roam_epoch - start_epoch) <= 2.0 or abs(roam_epoch - end_epoch) <= 2.0:
            return "roaming"
        if start_epoch <= roam_epoch <= end_epoch:
            return "roaming"

    # per_second에서 retry 비율 확인
    sec_start = int(start_epoch)
    sec_end = int(end_epoch) + 1
    total_frames = 0
    total_retry = 0
    for entry in per_second_timeline:
        if sec_start <= entry["epoch"] <= sec_end:
            total_frames += entry.get("total", 0)
            total_retry += entry.get("retry", 0)
    if total_frames > 0 and total_retry / total_frames > 0.3:
        return "high_retry"

    return "unknown"


def analyze_delays(
    ping_data: Dict[str, Any],
    roaming_data: Dict[str, Any],
    per_second_data: Dict[str, Any],
) -> Dict[str, Any]:
    """ping 데이터에서 지연 구간(delay zone)을 탐지한다.

    Returns:
        {"delay_zones": [...], "summary": {...}}
    """
    pairs = ping_data.get("pairs", [])
    losses = ping_data.get("losses", [])
    roaming_sequences = roaming_data.get("sequences", [])
    per_second_timeline = per_second_data.get("timeline", [])

    if not pairs and not losses:
        return {"delay_zones": [], "summary": {"total_zones": 0}}

    # RTT 이동 평균/표준편차 계산
    rtt_values = [p["rtt_ms"] for p in pairs]
    stats = _moving_avg_std(rtt_values, window=10) if rtt_values else []

    # 고RTT 포인트 탐지
    high_rtt_points: List[Dict] = []
    for i, pair in enumerate(pairs):
        if i < len(stats):
            avg, std = stats[i]
            rtt = pair["rtt_ms"]
            if rtt > avg * 2 or (std > 0 and rtt > avg + 2 * std):
                high_rtt_points.append({
                    "epoch": pair["epoch"],
                    "rtt_ms": rtt,
                    "avg_ms": avg,
                    "type": "high_rtt",
                })

    # loss 포인트 추가
    loss_points: List[Dict] = []
    for loss in losses:
        loss_points.append({
            "epoch": loss["epoch"],
            "rtt_ms": None,
            "type": "loss",
        })

    # 모든 이상 포인트 시간순 정렬
    all_points = sorted(high_rtt_points + loss_points, key=lambda x: x["epoch"])

    # 2초 이내 인접 포인트를 하나의 zone으로 그룹화
    zones: List[Dict] = []
    current_group: List[Dict] = []

    for pt in all_points:
        if not current_group:
            current_group.append(pt)
        elif pt["epoch"] - current_group[-1]["epoch"] <= 2.0:
            current_group.append(pt)
        else:
            zones.append(current_group)
            current_group = [pt]
    if current_group:
        zones.append(current_group)

    # zone별 요약 생성
    delay_zones: List[Dict] = []
    for group in zones:
        start_epoch = group[0]["epoch"]
        end_epoch = group[-1]["epoch"]
        duration = end_epoch - start_epoch
        rtt_vals = [p["rtt_ms"] for p in group if p["rtt_ms"] is not None]
        avg_rtt = round(sum(rtt_vals) / len(rtt_vals), 2) if rtt_vals else None

        cause = _find_cause(
            start_epoch, end_epoch,
            roaming_sequences, per_second_timeline,
        )

        delay_zones.append({
            "start_epoch": start_epoch,
            "end_epoch": end_epoch,
            "duration_sec": round(duration, 2),
            "affected_pings": len(group),
            "cause": cause,
            "avg_rtt_ms": avg_rtt,
        })

    return {
        "delay_zones": delay_zones,
        "summary": {
            "total_zones": len(delay_zones),
            "total_affected_pings": sum(z["affected_pings"] for z in delay_zones),
            "roaming_caused": sum(1 for z in delay_zones if z["cause"] == "roaming"),
            "retry_caused": sum(1 for z in delay_zones if z["cause"] == "high_retry"),
        },
    }
