"""웹 종합 진단(_structured_diagnosis)의 결론에 근거(frame_refs)+time_window를 부여.

종합 진단의 각 issue/sta_diag issue는 반드시 1개 이상의 stable tshark
frame.number(`frame_refs`)와 시간 구간(`time_window` = {start_epoch, end_epoch})을
실제 증거로부터 동반해야 한다(근거 없는 결론 0건). 이 모듈은 issue 종류별로
그 근거를 structured 데이터 + frames/index에서 소싱하는 헬퍼와, 모든 finding의
근거 프레임 합집합으로 디버그 타임라인용 `structured["debug"]` 블록을 만드는
빌더를 담는다.

대용량 캡처를 위해 frame_refs는 finding당 상한(`FRAME_REF_CAP`)을 두고, debug
블록의 frames도 합집합 후 상한(`DEBUG_FRAME_CAP`)을 둔다. 시계열은
timeline_series의 project_* 함수로 공유 시간축 위에 다운샘플해 bounded하게 유지.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.models import Frame
from .frame_table import frame_to_row
from ..core.detector import mac_name
from .timeline_axis import build_time_axis
from .timeline_series import (
    project_ping_series,
    project_retry_series,
    project_roaming_markers,
    project_rssi_series,
)

# finding 하나가 인용하는 frame_refs 상한 (대용량 캡처 안전).
FRAME_REF_CAP = 100
# debug 블록 frames(모든 finding 합집합 + 윈도우)의 상한.
DEBUG_FRAME_CAP = 2000
# finding의 time_window 양옆으로 debug 프레임에 포함할 윈도우(초).
DEBUG_WINDOW_PAD_SEC = 1.0


def _bounded_nums(nums: Sequence[int], limit: int = FRAME_REF_CAP) -> List[int]:
    """frame.number 리스트에 상한을 둔다. 초과 시 균등 샘플(첫/마지막 보존)."""
    nums = [n for n in nums if n is not None]
    if len(nums) <= limit:
        return list(nums)
    step = len(nums) / limit
    sampled = [nums[int(i * step)] for i in range(limit)]
    sampled[0] = nums[0]
    sampled[-1] = nums[-1]
    return sampled


def _window(epochs: Sequence[float]) -> Optional[Dict[str, float]]:
    """epoch 들의 범위를 time_window dict로. 비어있으면 None."""
    vals = [e for e in epochs if e is not None]
    if not vals:
        return None
    return {"start_epoch": min(vals), "end_epoch": max(vals)}


def _attach(issue: Dict[str, Any], frame_refs: List[int],
            time_window: Optional[Dict[str, float]]) -> bool:
    """frame_refs+time_window가 유효하면 issue에 부착하고 True 반환.

    근거를 댈 수 없으면(빈 frame_refs 또는 window 없음) 부착하지 않고 False
    반환 — 호출 측이 그 issue를 드롭한다(근거 없는 결론 금지).
    """
    if not frame_refs or time_window is None:
        return False
    issue["frame_refs"] = _bounded_nums(frame_refs)
    issue["time_window"] = time_window
    return True


def roaming_evidence(
    sequences: List[Dict[str, Any]], sta_mac: Optional[str] = None
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """로밍 시퀀스에서 auth/assoc frame.number + epoch 범위를 근거로 추출.

    sta_mac이 주어지면 그 STA의 시퀀스만, 없으면 전체 시퀀스를 본다.
    """
    seqs = sequences
    if sta_mac is not None:
        seqs = [s for s in sequences if s.get("sta") == sta_mac]
    nums: List[int] = []
    epochs: List[float] = []
    for s in seqs:
        for k in ("auth_fnum", "assoc_fnum"):
            n = s.get(k)
            if isinstance(n, int):
                nums.append(n)
        for k in ("auth_epoch", "assoc_epoch"):
            e = s.get(k)
            if isinstance(e, (int, float)):
                epochs.append(float(e))
    return nums, _window(epochs)


def slow_roaming_evidence(
    sequences: List[Dict[str, Any]], sta_mac: Optional[str] = None
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """느린 로밍(is_slow) 시퀀스만 근거로 추출."""
    slow = [s for s in sequences if s.get("is_slow")]
    return roaming_evidence(slow, sta_mac)


def ping_loss_evidence(
    losses: List[Dict[str, Any]],
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """손실 ping의 request frame.number + epoch 범위를 근거로 추출.

    loss_gap(가상 추정 손실)은 실제 손실 frame이 없어 req_num이 None이지만,
    추정의 시간 근거가 된 anchor 프레임 번호(anchor_num)를 frame_ref로 사용한다.
    모든 손실이 loss_gap인 단방향 캡처에서도 ping loss 결론이 근거 없음으로
    드롭되지 않도록 한다. epoch은 anchor에서 추정되므로 time_window에 포함한다.
    """
    nums: List[int] = []
    epochs: List[float] = []
    for item in losses:
        n = item.get("req_num")
        if not isinstance(n, int):
            # loss_gap: req_num이 없으면 anchor 프레임을 근거로 대체.
            n = item.get("anchor_num")
        if isinstance(n, int):
            nums.append(n)
        e = item.get("epoch")
        if isinstance(e, (int, float)):
            epochs.append(float(e))
    return nums, _window(epochs)


def retry_bucket_evidence(
    sta_mac: str, index: Any
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """STA의 retry 프레임 중 가장 retry가 많은 10초 버킷의 프레임을 근거로 추출.

    retry_pct 메트릭은 by_ta(TX)+by_ra(RX, 다운링크 재전송 포함) 양쪽으로
    계산되므로(structured._structured_device_stats), 근거도 같은 프레임 집합에서
    소싱한다. by_ta(TX)만 보면 다운링크 retry가 지배적인 STA의 retry 결론이
    근거 없음으로 드롭된다. 합친 프레임을 10초 버킷으로 묶고 retry 건수가 가장
    많은 버킷의 retry 프레임 frame.number와 그 버킷 epoch 범위를 반환한다.
    """
    if index is None:
        return [], None
    sta_frames = index.by_ta.get(sta_mac, []) + index.by_ra.get(sta_mac, [])
    retry_frames = [f for f in sta_frames if f.retry]
    if not retry_frames:
        return [], None
    from collections import defaultdict

    buckets: Dict[int, List[Frame]] = defaultdict(list)
    for f in retry_frames:
        buckets[int(f.epoch) // 10].append(f)
    worst = max(buckets, key=lambda b: len(buckets[b]))
    bucket_frames = buckets[worst]
    nums = [f.number for f in bucket_frames]
    epochs = [f.epoch for f in bucket_frames]
    return nums, _window(epochs)


def network_retry_evidence(
    frames: List[Frame], index: Any
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """네트워크 전체 retry 폭증 — 가장 retry가 많은 10초 버킷(전체 프레임 기준)."""
    retry_frames = [f for f in frames if f.retry]
    if not retry_frames:
        return [], None
    from collections import defaultdict

    buckets: Dict[int, List[Frame]] = defaultdict(list)
    for f in retry_frames:
        buckets[int(f.epoch) // 10].append(f)
    worst = max(buckets, key=lambda b: len(buckets[b]))
    bucket_frames = buckets[worst]
    return [f.number for f in bucket_frames], _window(
        [f.epoch for f in bucket_frames]
    )


_MODERN_PHY = ("HT", "VHT", "HE", "EHT")


def mcs_hotspot_evidence(
    sta_mac: str, phy: str, mcs_key: str, frames: List[Frame], index: Any
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """STA TX 중 특정 PHY+MCS에 해당하는 retry 프레임을 근거로 추출.

    modern PHY(HT/VHT/HE/EHT)는 mcs_int를 mcs_key(str)와 비교, Legacy는
    data_rate 첫 토큰을 mcs_key와 비교한다(structured의 mcs_retry_by_phy 키 규칙과
    동일). 매칭되는 retry 프레임이 없으면 ([], None) — _attach가 드롭한다.
    """
    if index is not None:
        tx = index.by_ta.get(sta_mac, [])
    else:
        tx = [f for f in frames if f.ta == sta_mac]
    matches: List[Frame] = []
    for f in tx:
        if not f.retry:
            continue
        f_phy = getattr(f, "mcs_phy", "") or ""
        if phy in _MODERN_PHY:
            if f_phy == phy and f.mcs_int is not None and str(f.mcs_int) == mcs_key:
                matches.append(f)
        else:
            # Legacy: modern PHY가 아닌 프레임의 data_rate 첫 토큰으로 매칭.
            if f_phy not in _MODERN_PHY and (
                getattr(f, "data_rate", "") or ""
            ).split(",")[0].strip() == mcs_key:
                matches.append(f)
    if not matches:
        return [], None
    return [f.number for f in matches], _window([f.epoch for f in matches])


def cliff_evidence(
    sta_mac: str,
    cliffs: List[Dict[str, Any]],
    frames: List[Frame],
    index: Any,
    pad_sec: float = 1.0,
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """신호 급강하(cliff) 이벤트 근처 STA 프레임을 근거로 추출.

    cliff 이벤트는 epoch만 가진다(frame.number 없음). 각 cliff epoch ±pad_sec
    안의 STA 송신 프레임 frame.number를 모으고, time_window는 cliff epoch들의
    범위로 만든다. 근처 프레임을 못 찾으면 가장 큰 cliff 근처 STA 최저 RSSI
    프레임으로 fallback해 결론이 드롭되지 않게 한다. 끝내 없으면 ([], None).
    """
    if not cliffs:
        return [], None
    # cliffs에 dict 아닌 항목(직렬화 잔재/오염)이 섞여도 c.get()이 터지지 않도록 필터.
    cliffs = [c for c in cliffs if isinstance(c, dict)]
    if not cliffs:
        return [], None
    if index is not None:
        sta_tx = index.by_ta.get(sta_mac, [])
    else:
        sta_tx = [f for f in frames if f.ta == sta_mac]
    cliff_epochs = [
        float(c["epoch"]) for c in cliffs
        if isinstance(c.get("epoch"), (int, float))
    ]
    if not cliff_epochs:
        return [], None
    nums: List[int] = []
    for f in sta_tx:
        if any(abs(f.epoch - ep) <= pad_sec for ep in cliff_epochs):
            nums.append(f.number)
    if not nums:
        # fallback: 가장 큰 drop을 가진 cliff 근처의 STA 최저 RSSI 프레임.
        worst = max(
            cliffs,
            key=lambda c: c.get("drop_db") or 0,
        )
        worst_ep = worst.get("epoch")
        near = [
            f for f in sta_tx
            if f.rssi_first is not None
            and isinstance(worst_ep, (int, float))
            and abs(f.epoch - worst_ep) <= max(pad_sec * 5, 5.0)
        ]
        if near:
            min_rssi = min(f.rssi_first for f in near)
            nums = [f.number for f in near if f.rssi_first == min_rssi]
    if not nums:
        return [], None
    return nums, _window(cliff_epochs)


def network_legacy_evidence(
    frames: List[Frame], index: Any
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """네트워크 전체 Legacy 송신(modern PHY 아님) 프레임을 근거로 추출.

    송신은 f.ta가 존재하는 프레임으로 보고, mcs_phy가 HT/VHT/HE/EHT가 아닌
    프레임을 Legacy로 분류한다(_device_entry_stats의 Legacy 판정과 동일).
    """
    legacy = [
        f for f in frames
        if f.ta and (getattr(f, "mcs_phy", "") or "") not in _MODERN_PHY
    ]
    if not legacy:
        return [], None
    return [f.number for f in legacy], _window([f.epoch for f in legacy])


def weak_rssi_evidence(
    sta_mac: str, threshold: int, frames: List[Frame], index: Any
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """STA 송신 프레임 중 RSSI가 threshold 미만인 약신호 프레임을 근거로 추출.

    임계 미만 프레임이 없으면(평균만 약하고 개별 샘플은 임계 위) RSSI 최저값
    근방 프레임으로 대체해 항상 1개 이상의 근거를 보장한다.
    """
    if index is not None:
        tx = [f for f in index.by_ta.get(sta_mac, []) if f.rssi_first is not None]
    else:
        tx = [f for f in frames if f.ta == sta_mac and f.rssi_first is not None]
    if not tx:
        return [], None
    weak = [f for f in tx if f.rssi_first < threshold]
    if not weak:
        # 임계 미만이 없으면 최저 RSSI 프레임을 대표 근거로.
        min_rssi = min(f.rssi_first for f in tx)
        weak = [f for f in tx if f.rssi_first == min_rssi]
    return [f.number for f in weak], _window([f.epoch for f in weak])


# anomaly type → 근거가 될 프레임을 고르는 필터.
#   deauth_disassoc: subtype 12(DeAuth)/10(DisAssoc)
#   excessive_probe_req: subtype 4(ProbeReq)
#   arp_storm: protocol == "ARP"
def anomaly_evidence(
    anomaly_type: str, frames: List[Frame]
) -> Tuple[List[int], Optional[Dict[str, float]]]:
    """이상(anomaly) 종류에 해당하는 실제 프레임을 근거로 추출.

    anomaly_frames는 집계 카운트만 가지므로(개별 epoch/frame 없음), 같은 종류의
    프레임을 캡처에서 직접 찾아 frame.number + epoch 범위를 근거로 만든다.
    """
    if anomaly_type == "deauth_disassoc":
        matches = [f for f in frames if f.subtype in ("10", "12")]
    elif anomaly_type == "excessive_probe_req":
        matches = [f for f in frames if f.subtype == "4"]
    elif anomaly_type == "arp_storm":
        matches = [f for f in frames if f.protocol == "ARP" or f.is_arp]
    else:
        matches = []
    if not matches:
        return [], None
    return [f.number for f in matches], _window([f.epoch for f in matches])


def build_debug_block(
    structured: Dict[str, Any],
    frames: List[Frame],
    index: Any,
    roles: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """디버그 타임라인용 structured["debug"] 블록을 만든다.

    - axis: 모든 metric 소스를 포괄하는 공유 시간축
    - series: rssi/retry/ping/roaming 을 공유 축 위에 다운샘플 투영
    - frames: 모든 finding의 frame_refs 합집합 + 양옆 윈도우 프레임을 frame_to_row로
      직렬화. 중복 제거 후 상한(DEBUG_FRAME_CAP)으로 bounded.
    """
    diagnosis = structured.get("diagnosis", {})
    signal = structured.get("signal", {})
    ping = structured.get("ping", {})
    roaming = structured.get("roaming", {})
    per_second = structured.get("per_second", {})

    # ── 공유 시간축: 모든 metric 소스를 포괄 ──
    rssi_samples: List[Dict[str, Any]] = []
    for bucket in ("stas", "aps"):
        for node in signal.get(bucket, {}).values():
            rssi_samples.extend(node.get("rssi_timeline", []))
    ping_full = ping.get("full_list", [])
    roam_seqs = roaming.get("sequences", [])
    per_sec_timeline = per_second.get("timeline", [])

    axis = build_time_axis(
        [rssi_samples, ping_full, roam_seqs, per_sec_timeline]
    )

    # roaming 시퀀스를 마커 투영용 이벤트(epoch/frame_number)로 평탄화.
    roam_events: List[Dict[str, Any]] = []
    for s in roam_seqs:
        if isinstance(s.get("auth_epoch"), (int, float)):
            roam_events.append({
                "kind": "auth",
                "epoch": float(s["auth_epoch"]),
                "frame_number": s.get("auth_fnum"),
                "sta": s.get("sta"),
                "ap": s.get("ap"),
            })
        if isinstance(s.get("assoc_epoch"), (int, float)):
            roam_events.append({
                "kind": "assoc",
                "epoch": float(s["assoc_epoch"]),
                "frame_number": s.get("assoc_fnum"),
                "sta": s.get("sta"),
                "ap": s.get("ap"),
            })

    # retry 시계열은 per-frame 단위로 투영한다. per_second 집계(초당 1 dict)를
    # project_retry_series(per-frame 가정)에 그대로 넣으면 bin의 total이 '프레임
    # 수'가 아니라 '초 수'로 집계돼 retry_pct가 수천 %까지 왜곡된다.
    retry_frame_samples = [{"epoch": f.epoch, "retry": f.retry} for f in frames]
    series = {
        "rssi": project_rssi_series(rssi_samples, axis),
        "retry": project_retry_series(retry_frame_samples, axis),
        "ping": project_ping_series(ping_full, axis),
        "roaming": project_roaming_markers(roam_events, axis),
    }

    # ── finding frame_refs 합집합 + 양옆 윈도우 프레임 ──
    ref_set: set = set()
    for issue in diagnosis.get("issues", []):
        ref_set.update(issue.get("frame_refs", []))
    for sd in diagnosis.get("sta_diags", []):
        for issue in sd.get("issues", []):
            ref_set.update(issue.get("frame_refs", []))

    by_number = {f.number: f for f in frames}
    chosen: Dict[int, Frame] = {}
    for n in ref_set:
        f = by_number.get(n)
        if f is not None:
            chosen[n] = f

    # 각 finding time_window 양옆 ±pad 의 프레임도 포함(증거 맥락).
    if index is not None and not axis.get("empty"):
        windows: List[Tuple[float, float]] = []
        for issue in diagnosis.get("issues", []):
            tw = issue.get("time_window")
            if tw:
                windows.append((tw["start_epoch"], tw["end_epoch"]))
        for sd in diagnosis.get("sta_diags", []):
            for issue in sd.get("issues", []):
                tw = issue.get("time_window")
                if tw:
                    windows.append((tw["start_epoch"], tw["end_epoch"]))
        for start, end in windows:
            if len(chosen) >= DEBUG_FRAME_CAP:
                break
            center = (start + end) / 2.0
            before = center - (start - DEBUG_WINDOW_PAD_SEC)
            after = (end + DEBUG_WINDOW_PAD_SEC) - center
            pre, post = index.frames_in_window(center, before, after)
            for f in pre + post:
                if f.number not in chosen:
                    chosen[f.number] = f
                if len(chosen) >= DEBUG_FRAME_CAP:
                    break

    # cited 근거 프레임(ref_set)은 절대 드롭하지 않는다 — finding의 '증거 보기'가
    # 가리키는 frame_ref가 표에서 사라지면 grounding 불변식이 깨지고 하이라이트가
    # 아무것도 못 찾는다. 따라서 맥락(padding) 프레임만 다운샘플해 전체를
    # DEBUG_FRAME_CAP 이하로 맞춘다(근거가 cap을 넘으면 근거 보존을 우선한다).
    evidence_frames = [f for n, f in chosen.items() if n in ref_set]
    padding_frames = [f for n, f in chosen.items() if n not in ref_set]
    budget = max(0, DEBUG_FRAME_CAP - len(evidence_frames))
    if len(padding_frames) > budget:
        if budget > 0:
            step = len(padding_frames) / budget
            padding_frames = [padding_frames[int(i * step)] for i in range(budget)]
        else:
            padding_frames = []
    ordered = sorted(
        evidence_frames + padding_frames, key=lambda f: (f.epoch, f.number)
    )

    # frame_to_row는 표시용 8개 컬럼만 담는다. 타임라인↔표 시간 동기화를 위해
    # 행마다 epoch을, 장치 필터를 위해 ta_name/ra_name을 부가한다(표에는 렌더되지
    # 않는 보조 키). roles가 없으면(단위 테스트 등) 이름 해석 없이 raw MAC을 싣고,
    # roles가 있으면 mac_name으로 STA/AP 표시명(장치 드롭다운 값과 동일)으로 환원한다.
    frame_rows: List[Dict[str, Any]] = []
    for f in ordered:
        row = frame_to_row(f)
        row["epoch"] = f.epoch
        if roles is not None:
            row["ta_name"] = mac_name(f.ta, roles) if f.ta else ""
            row["ra_name"] = mac_name(f.ra, roles) if f.ra else ""
        else:
            row["ta_name"] = f.ta or ""
            row["ra_name"] = f.ra or ""
        frame_rows.append(row)

    return {
        "axis": axis,
        "series": series,
        "frames": frame_rows,
    }
