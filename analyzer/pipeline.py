"""분석 파이프라인 오케스트레이션 — CLI와 웹 모두 이 모듈을 호출한다."""
import hashlib
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .core.extractor import extract_frames, detect_tshark_version
from .core.detector import detect_roles
from .core.indexer import FrameIndex
from .core.modules import (
    overview, retry_mcs, retry_burst, roaming, ping_rtt,
    control_traffic, signal_quality, per_second,
    roaming_impact, ping_loss, diagnosis,
)
from .web.delay_analysis import analyze_delays
from .web.anomaly_frames import detect_anomalies
from .web.signal_cliff import analyze_signal_cliffs
from .web.structured import (
    PING_MATCH_WINDOW_SEC,
    _structured_overview,
    _structured_signal,
    _structured_ping,
    _structured_roaming,
    _structured_per_second,
    _structured_device_stats,
    _structured_diagnosis,
)

__all__ = [
    "run_analysis",
    "PING_MATCH_WINDOW_SEC",
    "_structured_overview",
    "_structured_signal",
    "_structured_ping",
    "_structured_roaming",
    "_structured_per_second",
    "_structured_device_stats",
    "_structured_diagnosis",
]


def _make_id(pcap_path: str) -> str:
    ts = int(time.time())
    name = Path(pcap_path).stem
    h = hashlib.md5(pcap_path.encode()).hexdigest()[:8]
    return f"{ts}_{name}_{h}"


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
    import time as _time
    _tshark_path = _config.detect_tshark()
    _tshark_info = detect_tshark_version(_tshark_path or "tshark")

    # 추출 진행률: 시간·프레임 수에 따라 10→28%로 점진 (asymptotic, 절대 30 초과 안함)
    _extract_t0 = _time.time()
    def _frame_progress(count):
        elapsed = _time.time() - _extract_t0
        # 시간 기반 0~18% 추가 (60초쯤 12%, 5분쯤 17%)
        pct = 10 + int(18 * (1 - 1 / (1 + elapsed / 30)))
        _progress(f"tshark 추출... {count:,}프레임 처리됨", min(pct, 28))

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
        progress_cb=_frame_progress,
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
