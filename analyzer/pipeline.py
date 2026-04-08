"""분석 파이프라인 오케스트레이션 — CLI와 웹 모두 이 모듈을 호출한다."""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .core.extractor import extract_frames
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


def _structured_ping(frames: List[Frame], roles: Dict) -> Dict[str, Any]:
    """ping 전수검사 — 모든 ICMP Request/Reply를 seq 기준으로 매칭, timestamp 정렬."""
    from .core.detector import mac_name

    # 1단계: 모든 ICMP 프레임 수집
    all_requests = []  # (key, frame) 순서 보존
    requests_map = {}  # key → frame (매칭용)
    replies_map = {}   # key → frame
    matched = {}       # key → (req, reply)

    for f in frames:
        if f.is_icmp_request and not f.retry:
            key = (f.ip_src, f.ip_dst, f.icmp_seq) if f.icmp_seq else (f.ip_src, f.ip_dst, str(f.number))
            all_requests.append((key, f))
            requests_map[key] = f
        elif f.is_icmp_reply:
            key = (f.ip_dst, f.ip_src, f.icmp_seq) if f.icmp_seq else (f.ip_dst, f.ip_src, "")
            replies_map[key] = f

    # 2단계: Request→Reply 매칭
    for key, req in all_requests:
        reply = replies_map.pop(key, None)
        if reply:
            matched[key] = (req, reply)

    # 3단계: 전수 목록 생성 (timestamp 정렬)
    full_list = []
    pairs = []
    losses = []

    for key, req in all_requests:
        seq_str = key[2] if len(key) > 2 else ""
        if key in matched:
            req_f, reply_f = matched[key]
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
    """장치별 프레임 타입/서브타입 통계."""
    from collections import Counter
    from .core.models import SUBTYPE_NAMES
    result = {}
    for mac, info in roles.items():
        if index:
            dev_frames = index.by_ta.get(mac, []) + index.by_ra.get(mac, [])
        else:
            dev_frames = [f for f in frames if f.ta == mac or f.ra == mac]

        type_dist = Counter(f.frame_type for f in dev_frames)
        subtype_dist = Counter(f.subtype for f in dev_frames)
        retry_count = sum(1 for f in dev_frames if f.retry)

        subtype_named = {}
        for st, cnt in subtype_dist.most_common(20):
            name = SUBTYPE_NAMES.get(st, f"type={st}")
            subtype_named[name] = cnt

        result[info["name"]] = {
            "mac": mac,
            "role": info["role"],
            "total_frames": len(dev_frames),
            "type_dist": dict(type_dist),
            "subtype_dist": subtype_named,
            "retry_count": retry_count,
            "retry_pct": round(retry_count * 100 / len(dev_frames), 1) if dev_frames else 0,
        }
    return result


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
    frames = extract_frames(
        pcap_path,
        wpa_passphrase=passphrase,
        ssid=ssid,
        time_start=time_start,
        time_end=time_end,
        mac_filter=mac_filter,
        ip_filter=ip_filter,
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
        "structured": structured,
        "text_sections": text_report,
    }
