"""분석 파이프라인 오케스트레이션 — CLI와 웹 모두 이 모듈을 호출한다."""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .core.extractor import extract_frames, detect_tshark_version
from .core.detector import detect_roles
from .core.indexer import FrameIndex
from .core.models import Frame
from .core.modules import (
    overview, retry_mcs, retry_burst, roaming, ping_rtt,
    control_traffic, signal_quality, per_second,
    roaming_impact, ping_loss, diagnosis,
)
from .web.delay_analysis import analyze_delays
from .web.anomaly_frames import detect_anomalies
from .web.signal_cliff import analyze_signal_cliffs


def _make_id(pcap_path: str) -> str:
    ts = int(time.time())
    name = Path(pcap_path).stem
    h = hashlib.md5(pcap_path.encode()).hexdigest()[:8]
    return f"{ts}_{name}_{h}"


def _structured_overview(frames: List[Frame], roles: Dict, section) -> Dict[str, Any]:
    """overview 모듈의 텍스트 출력을 구조화된 dict로 변환."""
    n = len(frames)
    if n == 0:
        return {"total_frames": 0}

    from collections import Counter
    proto_counts = Counter(f.protocol for f in frames)
    subtype_counts = Counter(f.subtype for f in frames)
    retry_count = sum(1 for f in frames if f.retry)

    devices = []
    for mac, info in sorted(roles.items(), key=lambda x: x[1]["name"]):
        devices.append({
            "mac": mac,
            "role": info["role"],
            "name": info["name"],
            "count": info["count"],
        })

    return {
        "total_frames": n,
        "duration_sec": round(frames[-1].epoch - frames[0].epoch, 1),
        "time_start": frames[0].timestamp,
        "time_end": frames[-1].timestamp,
        "retry_count": retry_count,
        "retry_pct": round(retry_count * 100.0 / n, 2) if n else 0,
        "protocol_dist": dict(proto_counts.most_common(20)),
        "subtype_dist": dict(subtype_counts.most_common(20)),
        "devices": devices,
    }


def _structured_signal(frames: List[Frame], roles: Dict, index) -> Dict[str, Any]:
    """signal_quality + per_second 데이터를 시계열용으로 구조화."""
    sta_macs = [m for m, r in roles.items() if r["role"] == "STA"]
    result: Dict[str, Any] = {"stas": {}}

    for sta in sta_macs:
        name = roles[sta]["name"]
        if index:
            tx_frames = [f for f in index.by_ta.get(sta, []) if f.rssi_first is not None]
        else:
            tx_frames = [f for f in frames if f.ta == sta and f.rssi_first is not None]

        rssi_timeline = [
            {"epoch": f.epoch, "rssi": f.rssi_first, "mcs": f.mcs_int}
            for f in tx_frames
        ]
        result["stas"][name] = {
            "mac": sta,
            "rssi_timeline": rssi_timeline,
            "rssi_min": min((f.rssi_first for f in tx_frames), default=None),
            "rssi_max": max((f.rssi_first for f in tx_frames), default=None),
            "rssi_avg": round(sum(f.rssi_first for f in tx_frames) / len(tx_frames), 1) if tx_frames else None,
            "frame_count": len(tx_frames),
        }

    return result


PING_MATCH_WINDOW_SEC = 30.0


def _structured_ping(frames: List[Frame], roles: Dict) -> Dict[str, Any]:
    """ping 전수검사 — 모든 ICMP Request/Reply를 seq 기준으로 매칭, timestamp 정렬.

    같은 (src,dst,seq) 키가 재사용되는 경우를 위해 FIFO 큐로 매칭하고,
    PING_MATCH_WINDOW_SEC를 초과한 짝은 매치로 인정하지 않는다.
    """
    from .core.detector import mac_name

    all_requests = []           # (key, frame) 순서 보존
    requests_queue: Dict = {}   # key → list of pending req frames (FIFO)
    matched_by_req: Dict = {}   # id(req) → reply frame

    for f in frames:
        if f.is_icmp_request and not f.retry:
            key = (f.ip_src, f.ip_dst, f.icmp_seq) if f.icmp_seq else (f.ip_src, f.ip_dst, str(f.number))
            all_requests.append((key, f))
            requests_queue.setdefault(key, []).append(f)
        elif f.is_icmp_reply:
            key = (f.ip_dst, f.ip_src, f.icmp_seq) if f.icmp_seq else (f.ip_dst, f.ip_src, "")
            q = requests_queue.get(key)
            if not q:
                continue
            # 시간 윈도우 벗어난 오래된 요청은 큐에서 폐기
            while q and (f.epoch - q[0].epoch) > PING_MATCH_WINDOW_SEC:
                q.pop(0)
            if q:
                req = q.pop(0)
                matched_by_req[id(req)] = f

    # 3단계: 전수 목록 생성
    full_list = []
    pairs = []
    losses = []

    for key, req in all_requests:
        seq_str = key[2] if len(key) > 2 else ""
        reply_f = matched_by_req.get(id(req))
        if reply_f is not None:
            req_f = req
            rtt = (reply_f.epoch - req_f.epoch) * 1000
            entry = {
                "seq": seq_str,
                "status": "matched",
                "epoch": req_f.epoch,
                "rtt_ms": round(rtt, 2),
                "req_num": req_f.number,
                "req_time": req_f.time_short,
                "reply_num": reply_f.number,
                "reply_time": reply_f.time_short,
                "src": req_f.ip_src,
                "dst": req_f.ip_dst,
                "src_mac": mac_name(req_f.ta, roles) if req_f.ta else "",
                "dst_mac": mac_name(req_f.ra, roles) if req_f.ra else "",
                "has_retry": req_f.retry or reply_f.retry,
                "req_rssi": req_f.rssi_first,
            }
            full_list.append(entry)
            pairs.append(entry)
        else:
            entry = {
                "seq": seq_str,
                "status": "loss",
                "epoch": req.epoch,
                "rtt_ms": None,
                "req_num": req.number,
                "req_time": req.time_short,
                "reply_num": None,
                "reply_time": None,
                "src": req.ip_src,
                "dst": req.ip_dst,
                "src_mac": mac_name(req.ta, roles) if req.ta else "",
                "dst_mac": mac_name(req.ra, roles) if req.ra else "",
                "has_retry": req.retry,
                "req_rssi": req.rssi_first,
            }
            full_list.append(entry)
            losses.append(entry)

    # timestamp 정렬
    full_list.sort(key=lambda x: x["epoch"])
    pairs.sort(key=lambda x: x["epoch"])
    losses.sort(key=lambda x: x["epoch"])

    # 통계
    rtt_values = [p["rtt_ms"] for p in pairs]
    rtt_sorted = sorted(rtt_values) if rtt_values else []
    stats = {}
    if rtt_sorted:
        stats = {
            "count": len(rtt_sorted),
            "min": round(rtt_sorted[0], 2),
            "max": round(rtt_sorted[-1], 2),
            "avg": round(sum(rtt_sorted) / len(rtt_sorted), 2),
            "p50": round(rtt_sorted[len(rtt_sorted) // 2], 2),
            "p95": round(rtt_sorted[int(len(rtt_sorted) * 0.95)], 2),
            "p99": round(rtt_sorted[int(len(rtt_sorted) * 0.99)], 2),
            "loss_count": len(losses),
            "loss_pct": round(len(losses) * 100 / (len(pairs) + len(losses)), 1) if (pairs or losses) else 0,
        }

    return {
        "full_list": full_list,
        "pairs": pairs,
        "losses": losses,
        "stats": stats,
    }


def _structured_roaming(frames: List[Frame], roles: Dict) -> Dict[str, Any]:
    """roaming 이벤트를 구조화."""
    from .core.detector import mac_name
    roaming_frames = [f for f in frames if f.is_roaming_related]
    sta_macs = {mac for mac, role in roles.items() if role.get("role") == "STA"}

    sequences = []
    auth_events: Dict[str, Frame] = {}
    for frame in roaming_frames:
        if frame.subtype == "11" and frame.ta in sta_macs:
            auth_events[frame.ta] = frame
        elif frame.subtype in ("0", "2") and frame.ta in sta_macs:
            auth_frame = auth_events.get(frame.ta)
            if auth_frame is None:
                continue
            gap_ms = (frame.epoch - auth_frame.epoch) * 1000
            sequences.append({
                "sta": frame.ta,
                "sta_name": mac_name(frame.ta, roles),
                "ap": frame.ra,
                "ap_name": mac_name(frame.ra, roles),
                "auth_epoch": auth_frame.epoch,
                "assoc_epoch": frame.epoch,
                "auth_fnum": auth_frame.number,
                "assoc_fnum": frame.number,
                "gap_ms": round(gap_ms, 1),
                "assoc_type": frame.subtype_name,
                "is_slow": gap_ms > 100,
            })

    return {
        "roaming_frame_count": len(roaming_frames),
        "sequences": sequences,
    }


def _structured_per_second(frames: List[Frame]) -> Dict[str, Any]:
    """초당 프레임 수 시계열."""
    if not frames:
        return {"timeline": []}
    from collections import Counter
    sec_counts = Counter(int(f.epoch) for f in frames)
    retry_counts = Counter(int(f.epoch) for f in frames if f.retry)
    start = min(sec_counts)
    end = max(sec_counts)
    timeline = []
    for sec in range(start, end + 1):
        timeline.append({
            "epoch": sec,
            "total": sec_counts.get(sec, 0),
            "retry": retry_counts.get(sec, 0),
        })
    return {"timeline": timeline}


def _structured_device_stats(frames: List[Frame], roles: Dict, index) -> Dict[str, Any]:
    """장치별 프레임 타입/서브타입/MCS/RSSI/시간대별 통계."""
    from collections import Counter
    from .core.models import SUBTYPE_NAMES
    result = {}
    for mac, info in roles.items():
        if index:
            dev_frames = index.by_ta.get(mac, []) + index.by_ra.get(mac, [])
        else:
            dev_frames = [f for f in frames if f.ta == mac or f.ra == mac]

        if not dev_frames:
            continue

        type_dist = Counter(f.frame_type for f in dev_frames)
        subtype_dist = Counter(f.subtype for f in dev_frames)
        retry_count = sum(1 for f in dev_frames if f.retry)

        subtype_named = {}
        for st, cnt in subtype_dist.most_common(20):
            name = SUBTYPE_NAMES.get(st, f"type={st}")
            subtype_named[name] = cnt

        # MCS 분포 (TA 프레임만 — 해당 장치가 송신한 프레임)
        tx_frames = [f for f in dev_frames if f.ta == mac]
        mcs_dist = Counter(f.mcs_int for f in tx_frames if f.mcs_int is not None)
        mcs_named = {str(k): v for k, v in sorted(mcs_dist.items())}

        # RSSI 통계 (TA 프레임의 RSSI)
        rssis = [f.rssi_first for f in tx_frames if f.rssi_first is not None]
        rssi_stats = {}
        if rssis:
            rssi_sorted = sorted(rssis)
            rssi_stats = {
                "min": rssi_sorted[0],
                "max": rssi_sorted[-1],
                "avg": round(sum(rssis) / len(rssis), 1),
                "count": len(rssis),
            }

        # 시간대별 통계 (10초 구간)
        per_bucket = []
        if dev_frames:
            start_epoch = int(dev_frames[0].epoch)
            end_epoch = int(dev_frames[-1].epoch)
            bucket_size = 10  # 10초 구간
            per_bucket = []
            for bucket_start in range(start_epoch, end_epoch + 1, bucket_size):
                bucket_end = bucket_start + bucket_size
                bucket_frames = [f for f in dev_frames if bucket_start <= f.epoch < bucket_end]
                total = len(bucket_frames)
                retries = sum(1 for f in bucket_frames if f.retry)
                per_bucket.append({
                    "epoch": bucket_start,
                    "total": total,
                    "retry": retries,
                    "retry_pct": round(retries * 100 / total, 1) if total else 0,
                })

        result[info["name"]] = {
            "mac": mac,
            "role": info["role"],
            "total_frames": len(dev_frames),
            "tx_frames": len(tx_frames),
            "type_dist": dict(type_dist),
            "subtype_dist": subtype_named,
            "retry_count": retry_count,
            "retry_pct": round(retry_count * 100 / len(dev_frames), 1) if dev_frames else 0,
            "mcs_dist": mcs_named,
            "rssi_stats": rssi_stats,
            "per_bucket": per_bucket if dev_frames else [],
        }
    return result


def _structured_diagnosis(structured: Dict[str, Any]) -> Dict[str, Any]:
    """구조화된 종합 진단 — 네트워크 건강도 + STA별 상세 + 문제점 목록."""
    ov = structured.get("overview", {})
    ping = structured.get("ping", {})
    roaming = structured.get("roaming", {})
    signal = structured.get("signal", {})
    device_stats = structured.get("device_stats", {})
    delays = structured.get("delay_zones", {})
    anomalies = structured.get("anomaly_frames", {})

    total_frames = ov.get("total_frames", 0)
    retry_pct = ov.get("retry_pct", 0)
    ping_stats = ping.get("stats", {})
    loss_pct = ping_stats.get("loss_pct", 0)
    roam_seqs = roaming.get("sequences", [])
    slow_roams = [s for s in roam_seqs if s.get("is_slow")]

    # 개별 지표 점수 (0-100, 높을수록 좋음)
    retry_score = max(0, 100 - retry_pct * 5)  # 20%이면 0점
    loss_score = max(0, 100 - loss_pct * 10)  # 10%이면 0점
    roam_score = 100
    if len(roam_seqs) > 0:
        slow_ratio = len(slow_roams) / len(roam_seqs) * 100
        roam_score = max(0, 100 - slow_ratio * 2)

    # 전체 건강도 (가중 평균)
    health_score = round(retry_score * 0.3 + loss_score * 0.4 + roam_score * 0.3)
    if health_score >= 80:
        health_grade = "양호"
        health_color = "green"
    elif health_score >= 60:
        health_grade = "주의"
        health_color = "yellow"
    else:
        health_grade = "위험"
        health_color = "red"

    # STA별 상세 진단
    sta_diags = []
    stas = signal.get("stas", {})
    for sta_name, sta_info in stas.items():
        mac = sta_info.get("mac", "")
        ds = device_stats.get(sta_name, {})
        sta_retry = ds.get("retry_pct", 0)
        rssi_avg = sta_info.get("rssi_avg")
        rssi_min = sta_info.get("rssi_min")

        # STA별 로밍 횟수
        sta_roams = [s for s in roam_seqs if s.get("sta") == mac]
        sta_slow_roams = [s for s in sta_roams if s.get("is_slow")]

        # STA별 점수
        s_retry = max(0, 100 - sta_retry * 5)
        s_rssi = 100
        if rssi_avg is not None:
            s_rssi = max(0, min(100, (rssi_avg + 90) * 2.5))  # -90dBm=0, -50dBm=100
        s_roam = 100 if not sta_roams else max(0, 100 - len(sta_slow_roams) / max(len(sta_roams), 1) * 200)
        s_overall = round(s_retry * 0.35 + s_rssi * 0.35 + s_roam * 0.3)

        # 문제점
        issues = []
        if sta_retry > 25:
            issues.append({"severity": "high", "msg": f"Retry율 {sta_retry}% (임계치 25% 초과)", "action": "TX power 또는 안테나 확인, 로밍 임계값 조정"})
        elif sta_retry > 15:
            issues.append({"severity": "medium", "msg": f"Retry율 {sta_retry}%", "action": "채널 혼잡도 확인"})
        if rssi_avg is not None and rssi_avg < -70:
            issues.append({"severity": "high", "msg": f"RSSI 평균 {rssi_avg}dBm (약함)", "action": "AP 위치 조정 또는 TX power 증가"})
        elif rssi_avg is not None and rssi_avg < -60:
            issues.append({"severity": "medium", "msg": f"RSSI 평균 {rssi_avg}dBm", "action": "AP 커버리지 확인"})
        if len(sta_slow_roams) > 2:
            issues.append({"severity": "high", "msg": f"느린 로밍 {len(sta_slow_roams)}회 (>100ms)", "action": "802.11r/k/v 설정 확인, 로밍 히스테리시스 조정"})
        elif len(sta_roams) > 10:
            issues.append({"severity": "medium", "msg": f"잦은 로밍 {len(sta_roams)}회", "action": "로밍 트리거 RSSI 임계값 재설정"})

        sta_diags.append({
            "name": sta_name,
            "mac": mac,
            "score": s_overall,
            "scores": {"retry": round(s_retry), "rssi": round(s_rssi), "roaming": round(s_roam)},
            "metrics": {
                "retry_pct": sta_retry,
                "rssi_avg": rssi_avg,
                "rssi_min": rssi_min,
                "roaming_count": len(sta_roams),
                "slow_roaming": len(sta_slow_roams),
                "total_frames": ds.get("total_frames", 0),
            },
            "issues": issues,
        })

    # 전체 문제점 우선순위 목록
    all_issues = []
    # 네트워크 레벨
    if retry_pct > 15:
        all_issues.append({"severity": "high", "category": "Retry", "msg": f"네트워크 전체 Retry율 {retry_pct}%", "action": "채널 간섭 또는 AP 과부하 확인"})
    if loss_pct > 5:
        all_issues.append({"severity": "high", "category": "Ping", "msg": f"Ping Loss {loss_pct}%", "action": "네트워크 안정성 점검, 로밍 구간 확인"})
    if len(slow_roams) > 5:
        all_issues.append({"severity": "high", "category": "로밍", "msg": f"느린 로밍 {len(slow_roams)}회", "action": "802.11r Fast BSS Transition 활성화"})
    # anomaly
    anom_events = anomalies.get("anomalies", [])
    for a in anom_events:
        all_issues.append({"severity": a.get("severity", "medium"), "category": a.get("type", ""), "msg": a.get("description", ""), "action": a.get("recommendation", "")})
    # delay zones
    delay_zones = delays.get("delay_zones", [])
    if len(delay_zones) > 3:
        all_issues.append({"severity": "medium", "category": "지연", "msg": f"지연 구간 {len(delay_zones)}건 탐지", "action": "로밍/retry 상관관계 확인"})
    # STA별 이슈 통합
    for sd in sta_diags:
        for issue in sd["issues"]:
            all_issues.append({"severity": issue["severity"], "category": sd["name"], "msg": issue["msg"], "action": issue["action"]})

    # 심각도 정렬
    severity_order = {"high": 0, "medium": 1, "low": 2}
    all_issues.sort(key=lambda x: severity_order.get(x["severity"], 3))

    return {
        "health": {"score": health_score, "grade": health_grade, "color": health_color},
        "component_scores": {"retry": round(retry_score), "loss": round(loss_score), "roaming": round(roam_score)},
        "summary": {
            "total_frames": total_frames,
            "retry_pct": retry_pct,
            "loss_pct": loss_pct,
            "roaming_total": len(roam_seqs),
            "roaming_slow": len(slow_roams),
            "delay_zones": len(delay_zones),
            "anomaly_count": len(anom_events),
        },
        "sta_diags": sta_diags,
        "issues": all_issues,
    }


def run_analysis(
    pcap_path: str,
    ssid: str = "",
    passphrase: str = "",
    time_start: str = "",
    time_end: str = "",
    mac_filter: str = "",
    ip_filter: str = "",
    progress_cb: Optional[Callable[[str, int], None]] = None,
    cancel_event: Optional[Any] = None,
) -> Dict[str, Any]:
    """전체 분석 파이프라인 실행. 구조화된 결과를 반환."""

    def _cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    def _progress(msg: str, pct: int = 0):
        if progress_cb:
            progress_cb(msg, pct)

    if _cancelled():
        return {"cancelled": True}

    _progress("tshark로 프레임 추출 중...", 10)
    import config as _config
    _tshark_path = _config.detect_tshark()
    _tshark_info = detect_tshark_version(_tshark_path or "tshark")
    frames = extract_frames(
        pcap_path,
        wpa_passphrase=passphrase,
        ssid=ssid,
        time_start=time_start,
        time_end=time_end,
        mac_filter=mac_filter,
        ip_filter=ip_filter,
        tshark_path=_tshark_path,
        cancel_event=cancel_event,
    )
    if not frames:
        return {"error": "프레임을 추출하지 못했습니다. tshark 경로 또는 pcap 파일을 확인하세요."}

    if _cancelled():
        return {"cancelled": True}

    _progress(f"{len(frames):,}프레임 추출 완료. 역할 감지 중...", 30)
    roles = detect_roles(frames)

    if _cancelled():
        return {"cancelled": True}

    _progress("프레임 인덱싱 중...", 40)
    index = FrameIndex(frames, roles)

    _progress("분석 모듈 실행 중...", 50)

    # 텍스트 섹션 (기존 호환)
    analyzer_list = [
        ("개요", overview),
        ("Retry MCS", retry_mcs),
        ("Retry Burst", retry_burst),
        ("로밍", roaming),
        ("Ping RTT", ping_rtt),
        ("제어 트래픽", control_traffic),
        ("신호 품질", signal_quality),
        ("초당 통계", per_second),
        ("로밍 영향", roaming_impact),
        ("Ping Loss", ping_loss),
        ("종합 진단", diagnosis),
    ]
    text_sections = []
    for i, (name, mod) in enumerate(analyzer_list):
        if _cancelled():
            return {"cancelled": True}
        _progress(f"{name} 분석...", 50 + int(40 * i / len(analyzer_list)))
        text_sections.append(mod.analyze(frames, roles, index))

    # 구조화된 데이터 (웹 시각화용)
    _progress("시각화 데이터 생성 중...", 90)
    overview_section = text_sections[0]
    structured = {
        "overview": _structured_overview(frames, roles, overview_section),
        "signal": _structured_signal(frames, roles, index),
        "ping": _structured_ping(frames, roles),
        "roaming": _structured_roaming(frames, roles),
        "per_second": _structured_per_second(frames),
        "device_stats": _structured_device_stats(frames, roles, index),
    }
    structured["delay_zones"] = analyze_delays(structured["ping"], structured["roaming"], structured["per_second"])
    structured["anomaly_frames"] = detect_anomalies(structured["overview"])
    structured["signal_cliffs"] = analyze_signal_cliffs(structured["signal"])
    structured["diagnosis"] = _structured_diagnosis(structured)

    # 텍스트 리포트 (호환용)
    text_report = []
    for sec in text_sections:
        text_report.append({"title": sec.title, "summary": sec.summary, "lines": sec.lines})

    _progress("완료!", 100)
    return {
        "id": _make_id(pcap_path),
        "pcap_name": Path(pcap_path).name,
        "pcap_size": os.path.getsize(pcap_path),
        "frame_count": len(frames),
        "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tshark_version": _tshark_info["version"],
        "tshark_path": _tshark_info["path"],
        "structured": structured,
        "text_sections": text_report,
    }
