"""디버그 모드 타임라인용 per-metric 시계열 투영(projection).

디버그 화면은 RSSI / retry / ping / roaming 시계열을 Sub-AC 1이 만든 **공유
시간축**(`timeline_axis.build_time_axis`) 위에 겹쳐 그린다. 각 metric의 raw
샘플을 그대로 그리면 대용량 캡처(수백만 프레임)에서 포인트가 폭증하므로, 먼저
샘플들을 공유 축의 bin으로 버킷팅(다운샘플)해 축 그리드에 정렬된 시간순 포인트
리스트로 투영한다.

이 모듈은 RSSI 투영(`project_rssi_series`), retry 투영(`project_retry_series`),
ping 성공·손실 투영(`project_ping_series`), 그리고 roaming 이벤트 마커 투영
(`project_roaming_markers`)을 담당한다.

RSSI/retry/ping은 고빈도 샘플이라 bin 버킷으로 다운샘플하지만, roaming
이벤트(Auth/Reassoc 등)는 희소한 개별 사건이므로 각 이벤트를 **개별 마커**로
유지하면서 동일한 공유 축의 bin 위치에만 정렬한다(각 마커는 정확한 epoch과
증거용 frame.number를 보존 → 사용자가 그 프레임으로 점프 가능).
"""
from typing import Any, Dict, FrozenSet, List, Optional, Sequence

from analyzer.web.timeline_axis import bin_index_for

# structured.py의 rssi_timeline 항목은 {"epoch": float, "rssi": int, "mcs": ...}.
DEFAULT_EPOCH_KEY = "epoch"
DEFAULT_VALUE_KEY = "rssi"
# structured.py의 per_second/프레임 항목은 retry를 bool 플래그 또는 카운트로 담는다.
DEFAULT_RETRY_KEY = "retry"
# ping_matching.py가 만드는 ping outcome entry는 결과를 "status"로 담는다.
DEFAULT_STATUS_KEY = "status"
# ping_matching.py의 상태값과 일치:
#   성공 = 양방향 매칭된 echo request/reply ("matched")
#   손실 = 확정 무선 손실("loss") + seq-gap 추정 손실("loss_gap")
PING_SUCCESS_STATUSES: FrozenSet[str] = frozenset({"matched"})
PING_LOSS_STATUSES: FrozenSet[str] = frozenset({"loss", "loss_gap"})


def _as_number(value: Any) -> Optional[float]:
    """bool을 배제하고 int/float만 float로 변환. 그 외엔 None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def project_rssi_series(
    samples: Sequence[Dict[str, Any]],
    axis: Dict[str, Any],
    epoch_key: str = DEFAULT_EPOCH_KEY,
    value_key: str = DEFAULT_VALUE_KEY,
) -> List[Dict[str, Any]]:
    """RSSI 샘플들을 공유 시간축 위 bin으로 투영한다.

    각 샘플을 `bin_index_for`로 축의 bin에 버킷팅하고, bin별 평균/최소/최대 RSSI를
    계산한다. 결과 포인트는 bin 인덱스 오름차순(= 시간순)으로 정렬되며, 각 포인트의
    `epoch`은 해당 bin의 왼쪽 경계(축 그리드에 정렬됨)이다.

    Args:
        samples: RSSI 샘플 dict들. 예: structured.py의 rssi_timeline
            (`{"epoch": float, "rssi": int}`). epoch/value가 없거나 숫자가 아니거나
            bool인 항목은 건너뛴다.
        axis: `build_time_axis`가 만든 공유 시간축.
        epoch_key: 샘플에서 epoch을 읽을 키.
        value_key: 샘플에서 RSSI 값을 읽을 키.

    Returns:
        시간순으로 정렬된 포인트 리스트. 각 포인트:
        {
            "bin": int,        # 공유 축 bin 인덱스 [0, bin_count-1]
            "epoch": float,    # 해당 bin의 왼쪽 경계 epoch (축 그리드에 정렬)
            "rssi": float,     # bin 내 RSSI 평균 (소수 1자리 반올림)
            "rssi_min": int,   # bin 내 최소 RSSI
            "rssi_max": int,   # bin 내 최대 RSSI
            "count": int,      # bin에 집계된 샘플 수
        }

        출력 포인트 수는 비어있지 않은 bin 수 이하이며, 항상 `axis["bin_count"]`를
        넘지 않는다(대용량 캡처 다운샘플링).
    """
    bin_count = axis.get("bin_count", 0)
    bins = axis.get("bins", [])
    if not bin_count or not bins:
        return []

    # bin 인덱스 → 누적 집계 버킷.
    buckets: Dict[int, Dict[str, Any]] = {}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        epoch = _as_number(sample.get(epoch_key))
        value = _as_number(sample.get(value_key))
        if epoch is None or value is None:
            continue

        idx = bin_index_for(axis, epoch)
        bucket = buckets.get(idx)
        if bucket is None:
            buckets[idx] = {
                "sum": value,
                "min": value,
                "max": value,
                "count": 1,
            }
        else:
            bucket["sum"] += value
            bucket["count"] += 1
            if value < bucket["min"]:
                bucket["min"] = value
            if value > bucket["max"]:
                bucket["max"] = value

    points: List[Dict[str, Any]] = []
    # bin 인덱스 오름차순 = 시간순. epoch은 축 그리드의 bin 왼쪽 경계로 정렬.
    for idx in sorted(buckets):
        bucket = buckets[idx]
        count = bucket["count"]
        points.append(
            {
                "bin": idx,
                "epoch": bins[idx],
                "rssi": round(bucket["sum"] / count, 1),
                "rssi_min": int(bucket["min"]),
                "rssi_max": int(bucket["max"]),
                "count": count,
            }
        )
    return points


def _retry_units(value: Any) -> int:
    """프레임의 retry 값을 retry '건수'로 정규화한다.

    Frame.retry는 bool 플래그지만 소스에 따라 카운트(int)로 들어올 수도 있어
    둘 다 받는다("counts/flags"):
        - True  → 1, False → 0
        - int/float(비-bool) → max(0, int(value)) (음수는 0)
        - None/그 외 → 0 (프레임 자체는 total에 집계되되 retry는 0)
    """
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        n = int(value)
        return n if n > 0 else 0
    return 0


def project_retry_series(
    frames: Sequence[Dict[str, Any]],
    axis: Dict[str, Any],
    epoch_key: str = DEFAULT_EPOCH_KEY,
    retry_key: str = DEFAULT_RETRY_KEY,
) -> List[Dict[str, Any]]:
    """per-frame retry 플래그/카운트를 공유 시간축 위 bin으로 투영한다.

    RSSI 투영(`project_rssi_series`)과 **동일한 공유 축**(`build_time_axis`)·동일한
    `bin_index_for` 매핑을 사용하므로, 같은 epoch의 retry/RSSI 샘플은 항상 같은 bin
    인덱스(=같은 시간축 위치)에 정렬된다. 각 프레임을 bin에 버킷팅해 bin별 retry
    건수·전체 프레임 수·retry 비율을 집계한다(대용량 캡처 다운샘플).

    Args:
        frames: per-frame dict들. 예: `{"epoch": float, "retry": bool}`
            (structured.py per_second는 retry를 카운트로 담으므로 int도 허용).
            epoch이 없거나 숫자가 아니거나 bool인 항목은 건너뛴다. retry 키가
            없으면 그 프레임은 비-retry 프레임(total에는 집계, retry 0)으로 본다.
        axis: `build_time_axis`가 만든 공유 시간축(RSSI 투영과 동일 축).
        epoch_key: 프레임에서 epoch을 읽을 키.
        retry_key: 프레임에서 retry 플래그/카운트를 읽을 키.

    Returns:
        시간순으로 정렬된 포인트 리스트. 각 포인트:
        {
            "bin": int,         # 공유 축 bin 인덱스 [0, bin_count-1]
            "epoch": float,     # 해당 bin의 왼쪽 경계 epoch (축 그리드에 정렬)
            "retry": int,       # bin 내 retry 건수
            "total": int,       # bin 내 전체 프레임 수
            "retry_pct": float, # retry/total*100 (소수 1자리), total==0이면 0.0
            "count": int,       # bin에 집계된 프레임 수 (== total)
        }

        출력 포인트 수는 비어있지 않은 bin 수 이하이며, 항상 `axis["bin_count"]`를
        넘지 않는다(대용량 캡처 다운샘플링).
    """
    bin_count = axis.get("bin_count", 0)
    bins = axis.get("bins", [])
    if not bin_count or not bins:
        return []

    # bin 인덱스 → 누적 집계 버킷.
    buckets: Dict[int, Dict[str, int]] = {}
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        epoch = _as_number(frame.get(epoch_key))
        if epoch is None:
            continue

        retries = _retry_units(frame.get(retry_key))
        idx = bin_index_for(axis, epoch)
        bucket = buckets.get(idx)
        if bucket is None:
            buckets[idx] = {"retry": retries, "total": 1}
        else:
            bucket["retry"] += retries
            bucket["total"] += 1

    points: List[Dict[str, Any]] = []
    # bin 인덱스 오름차순 = 시간순. epoch은 축 그리드의 bin 왼쪽 경계로 정렬
    # (project_rssi_series와 동일한 정렬 규칙 → 같은 축 위 같은 bin).
    for idx in sorted(buckets):
        bucket = buckets[idx]
        total = bucket["total"]
        retries = bucket["retry"]
        points.append(
            {
                "bin": idx,
                "epoch": bins[idx],
                "retry": retries,
                "total": total,
                "retry_pct": round(retries * 100.0 / total, 1) if total else 0.0,
                "count": total,
            }
        )
    return points


def _ping_outcome(
    status: Any,
    success_statuses: FrozenSet[str],
    loss_statuses: FrozenSet[str],
) -> Optional[str]:
    """ping outcome entry의 status를 success/loss 둘 중 하나로 정규화한다.

    분류 불가(예: "observed" 처럼 측정 불가)면 None — 그 entry는 성공/손실
    어느 카운트에도 잡히지 않고 건너뛴다.
    """
    if status in success_statuses:
        return "success"
    if status in loss_statuses:
        return "loss"
    return None


def project_ping_series(
    events: Sequence[Dict[str, Any]],
    axis: Dict[str, Any],
    epoch_key: str = DEFAULT_EPOCH_KEY,
    status_key: str = DEFAULT_STATUS_KEY,
    success_statuses: FrozenSet[str] = PING_SUCCESS_STATUSES,
    loss_statuses: FrozenSet[str] = PING_LOSS_STATUSES,
) -> List[Dict[str, Any]]:
    """ping 성공/손실 outcome을 공유 시간축 위 bin으로 투영한다.

    RSSI 투영(`project_rssi_series`)·retry 투영(`project_retry_series`)과 **동일한
    공유 축**(`build_time_axis`)·동일한 `bin_index_for` 매핑을 사용하므로, 같은
    epoch의 ping/RSSI/retry 샘플은 항상 같은 bin 인덱스(=같은 시간축 위치)에
    정렬된다. 각 ping outcome을 bin에 버킷팅해 bin별 성공/손실 건수·손실 비율을
    집계한다(대용량 캡처 다운샘플).

    Args:
        events: ping outcome dict들. 예: ping_matching.py `build_ping_matches`의
            `full_list`/`pairs`+`losses` 항목 (`{"epoch": float, "status": str}`).
            성공 = status ∈ success_statuses("matched"), 손실 = status ∈
            loss_statuses("loss"/"loss_gap"). epoch이 없거나 숫자가 아니거나
            bool인 항목, 성공·손실 어느 쪽도 아닌 status는 건너뛴다.
        axis: `build_time_axis`가 만든 공유 시간축(RSSI/retry 투영과 동일 축).
        epoch_key: outcome에서 epoch을 읽을 키.
        status_key: outcome에서 성공/손실 status를 읽을 키.
        success_statuses: 성공으로 간주할 status 집합.
        loss_statuses: 손실로 간주할 status 집합.

    Returns:
        시간순으로 정렬된 포인트 리스트. 각 포인트:
        {
            "bin": int,        # 공유 축 bin 인덱스 [0, bin_count-1]
            "epoch": float,    # 해당 bin의 왼쪽 경계 epoch (축 그리드에 정렬)
            "success": int,    # bin 내 ping 성공 건수
            "loss": int,       # bin 내 ping 손실 건수
            "total": int,      # bin 내 성공+손실 건수
            "loss_pct": float, # loss/total*100 (소수 1자리), total==0이면 0.0
            "count": int,      # bin에 집계된 outcome 수 (== total)
        }

        출력 포인트 수는 비어있지 않은 bin 수 이하이며, 항상 `axis["bin_count"]`를
        넘지 않는다(대용량 캡처 다운샘플링).
    """
    bin_count = axis.get("bin_count", 0)
    bins = axis.get("bins", [])
    if not bin_count or not bins:
        return []

    # bin 인덱스 → 누적 집계 버킷.
    buckets: Dict[int, Dict[str, int]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        epoch = _as_number(event.get(epoch_key))
        if epoch is None:
            continue
        outcome = _ping_outcome(
            event.get(status_key), success_statuses, loss_statuses
        )
        if outcome is None:
            continue

        idx = bin_index_for(axis, epoch)
        bucket = buckets.get(idx)
        if bucket is None:
            bucket = buckets[idx] = {"success": 0, "loss": 0}
        bucket[outcome] += 1

    points: List[Dict[str, Any]] = []
    # bin 인덱스 오름차순 = 시간순. epoch은 축 그리드의 bin 왼쪽 경계로 정렬
    # (project_rssi_series/project_retry_series와 동일한 정렬 규칙 → 같은 축 위 같은 bin).
    for idx in sorted(buckets):
        bucket = buckets[idx]
        success = bucket["success"]
        loss = bucket["loss"]
        total = success + loss
        points.append(
            {
                "bin": idx,
                "epoch": bins[idx],
                "success": success,
                "loss": loss,
                "total": total,
                "loss_pct": round(loss * 100.0 / total, 1) if total else 0.0,
                "count": total,
            }
        )
    return points


# roaming 마커가 기본으로 보존하는 이벤트 필드(있을 때만 마커로 복사).
DEFAULT_ROAMING_PASSTHROUGH = (
    "kind",
    "frame_number",
    "sta",
    "ap",
    "subtype",
    "subtype_name",
    "time_short",
)


def project_roaming_markers(
    events: Sequence[Dict[str, Any]],
    axis: Dict[str, Any],
    epoch_key: str = DEFAULT_EPOCH_KEY,
    passthrough_keys: Sequence[str] = DEFAULT_ROAMING_PASSTHROUGH,
) -> List[Dict[str, Any]]:
    """roaming 이벤트(Auth/Reassoc 등)를 공유 시간축 위 개별 마커로 투영한다.

    RSSI/retry/ping 투영과 **동일한 공유 축**(`build_time_axis`)·동일한
    `bin_index_for` 매핑을 사용하므로, 같은 epoch의 roaming 이벤트는 다른 metric
    시계열과 항상 같은 bin 인덱스(=같은 시간축 위치)에 정렬된다. RSSI/retry/ping은
    bin 버킷으로 다운샘플되지만, roaming 이벤트는 희소한 개별 사건이므로 버킷팅하지
    않고 **각 이벤트를 하나의 마커로 그대로** 보존한다 — 각 마커는 정확한 epoch과
    증거용 frame.number를 담아 사용자가 그 프레임으로 점프할 수 있게 한다.

    Args:
        events: roaming 이벤트 dict들. 예: `roaming.extract_roaming_events`의 출력
            (`{"kind", "epoch", "frame_number", "sta", "ap", ...}`). epoch이
            없거나 숫자가 아니거나 bool인 항목은 건너뛴다.
        axis: `build_time_axis`가 만든 공유 시간축(다른 metric 투영과 동일 축).
        epoch_key: 이벤트에서 epoch을 읽을 키.
        passthrough_keys: 마커로 복사할 이벤트 필드들(존재하는 키만 복사).

    Returns:
        epoch 오름차순(시간순)으로 정렬된 마커 리스트. 각 마커:
        {
            "bin": int,        # 공유 축 bin 인덱스 [0, bin_count-1]
            "epoch": float,    # 이벤트의 실제 발생 시각(정확한 timestamp)
            "bin_epoch": float,# 해당 bin의 왼쪽 경계 epoch (축 그리드에 정렬)
            ... passthrough_keys 중 존재하는 필드 (kind/frame_number/sta/ap 등)
        }

        `bin_index_for(axis, marker["epoch"]) == marker["bin"]` 가 항상 성립하며,
        `marker["bin_epoch"] == axis["bins"][marker["bin"]]` 로 다른 시계열과 같은
        축 그리드에 정렬된다.
    """
    bin_count = axis.get("bin_count", 0)
    bins = axis.get("bins", [])
    if not bin_count or not bins:
        return []

    markers: List[Dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        epoch = _as_number(event.get(epoch_key))
        if epoch is None:
            continue

        idx = bin_index_for(axis, epoch)
        marker: Dict[str, Any] = {
            "bin": idx,
            "epoch": epoch,
            "bin_epoch": bins[idx],
        }
        for key in passthrough_keys:
            if key in event:
                marker[key] = event[key]
        markers.append(marker)

    # epoch 오름차순(시간순). 같은 epoch은 입력 순서 유지(stable sort).
    markers.sort(key=lambda m: m["epoch"])
    return markers
