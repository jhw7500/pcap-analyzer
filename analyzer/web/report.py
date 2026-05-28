"""분석 결과 → 외부 공유용 마크다운 리포트 직렬화.

사용자가 분석 페이지에서 본 내용(메타데이터, 종합 결론, 단일 진단, STA별
진단, AI 가설)을 단일 마크다운 파일로 export. 외부 도구(pandoc, gstack,
typora 등)로 PDF/HTML로 추가 변환 가능하도록 표준 GFM 사양 준수.

차트(미니차트, 메인 타임라인)는 텍스트 요약(bin별 RSSI/Retry/Loss/Roaming
대표값)으로 노출 — SVG/PNG inline은 후속 PR(PDF export)에서 다룬다.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# 결합 신호 type → 한국어 라벨. JS SIGNAL_TYPE_LABEL과 의도적으로 동기화 —
# 새 type 추가 시 charts.js의 같은 맵도 갱신.
SIGNAL_TYPE_LABEL = {
    "weak_rssi": "약신호",
    "high_retry": "retry 폭증",
    "slow_roaming": "슬로우 로밍",
    "frequent_roaming": "잦은 로밍",
    "high_loss": "Ping Loss",
    "delay_zone": "지연 구간",
    "anomaly": "이상 프레임",
}


def _format_epoch(epoch: Any) -> str:
    """epoch 초 → 'YYYY-MM-DD HH:MM:SS UTC'. 실패 시 빈 문자열.

    UTC 고정 — 호스트 timezone에 따라 리포트 시각이 달라지면 같은 분석을
    다른 환경에서 재현한 리포트가 다른 값으로 보이게 됨. 사용자가 본인
    환경 시간대로 보고 싶으면 변환은 후처리(pandoc/typora 등)에 맡긴다.
    """
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _meta_section(result: Dict[str, Any]) -> List[str]:
    """리포트 헤더 + 메타데이터 블록."""
    lines = ["# WLAN Pcap 종합 분석 리포트", ""]
    pcap_name = result.get("pcap_name") or "?"
    lines.append(f"**파일**: `{pcap_name}`")
    overview = (result.get("structured") or {}).get("overview") or {}
    pairs: List[str] = []
    if result.get("analyzed_at"):
        pairs.append(f"분석 시각 `{result['analyzed_at']}`")
    if result.get("tshark_version"):
        pairs.append(f"tshark `{result['tshark_version']}`")
    if overview.get("duration_sec") is not None:
        pairs.append(f"캡처 시간 {overview['duration_sec']}s")
    if overview.get("total_frames") is not None:
        pairs.append(f"프레임 {overview['total_frames']:,}건")
    if result.get("pcap_size"):
        pairs.append(f"크기 {result['pcap_size']:,}B")
    if pairs:
        lines.append(" · ".join(pairs))
    lines.append("")
    return lines


def _correlations_section(diagnosis: Dict[str, Any]) -> List[str]:
    """종합 결론 (다중 신호 결합). LLM의 ### C{n} 헤더와 짝짓도록 같은 번호 체계."""
    correlations = diagnosis.get("correlations") or []
    if not isinstance(correlations, list):
        return []
    valid = [c for c in correlations if isinstance(c, dict)]
    if not valid:
        return []
    lines = ["## 종합 진단 (다중 신호 결합)", ""]
    for n, c in enumerate(valid, start=1):
        try:
            conf = float(c.get("confidence", 0))
        except (TypeError, ValueError):
            conf = 0.0
        title = c.get("title", "?")
        sta = c.get("sta_name") or c.get("sta_mac") or "?"
        lines.append(f"### C{n}: {title} (conf={conf:.2f})")
        lines.append(f"- STA: `{sta}`")
        tw = c.get("time_window")
        if isinstance(tw, dict):
            s_str = _format_epoch(tw.get("start_epoch"))
            e_str = _format_epoch(tw.get("end_epoch"))
            if s_str and e_str:
                lines.append(f"- 시간 구간: {s_str} ~ {e_str}")
        sigs = []
        signals = c.get("signals")
        if isinstance(signals, list):
            for s in signals:
                if isinstance(s, dict):
                    stype = s.get("type", "?")
                    label = SIGNAL_TYPE_LABEL.get(stype, stype)
                    sigs.append(label)
        if sigs:
            lines.append(f"- 결합 신호: {', '.join(sigs)}")
        frame_refs = c.get("frame_refs")
        n_refs = len(frame_refs) if isinstance(frame_refs, list) else 0
        if n_refs:
            lines.append(f"- 증거 프레임: {n_refs:,}건")
        explanation = (c.get("explanation") or "").strip()
        if explanation:
            lines.append(f"- 단일 결론 요약: {explanation}")
        lines.append("")
    return lines


def _issues_table(diagnosis: Dict[str, Any]) -> List[str]:
    """단일 진단 결론(issues) 마크다운 표."""
    issues = diagnosis.get("issues") or []
    if not isinstance(issues, list) or not issues:
        return []
    lines = ["## 단일 진단 결론", ""]
    lines.append("| Severity | Category | 문제 | 조치 |")
    lines.append("|---|---|---|---|")
    for iss in issues:
        if not isinstance(iss, dict):
            continue
        sev = iss.get("severity", "?")
        cat = iss.get("category", iss.get("type", "?"))
        # `|`는 표 row를 깨고, 줄바꿈은 row 자체를 두 row로 분할해 GFM 표 layout
        # 을 망가뜨린다. 둘 다 안전 문자로 치환.
        def _clean_cell(s: str) -> str:
            return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
        msg = _clean_cell(iss.get("msg") or "")
        action = _clean_cell(iss.get("action") or iss.get("recommendation") or "")
        lines.append(f"| {sev} | {cat} | {msg} | {action} |")
    lines.append("")
    return lines


def _sta_diags_section(diagnosis: Dict[str, Any]) -> List[str]:
    """STA별 진단 상세."""
    sta_diags = diagnosis.get("sta_diags") or []
    if not isinstance(sta_diags, list) or not sta_diags:
        return []
    lines = ["## STA별 진단", ""]
    for sd in sta_diags:
        if not isinstance(sd, dict):
            continue
        name = sd.get("name", "?")
        mac = sd.get("mac", "")
        score = sd.get("score")
        lines.append(f"### {name} `{mac}`")
        if score is not None:
            lines.append(f"- 점수: **{score}**/100")
        raw_metrics = sd.get("metrics")
        metrics = raw_metrics if isinstance(raw_metrics, dict) else {}
        m_parts = []
        for k, label in (
            ("retry_pct", "Retry"),
            ("rssi_avg", "RSSI 평균(dBm)"),
            ("rssi_min", "RSSI 최저(dBm)"),
            ("roaming_count", "로밍"),
            ("slow_roaming", "느린 로밍"),
            ("total_frames", "프레임"),
        ):
            v = metrics.get(k)
            if v is not None:
                m_parts.append(f"{label} {v}")
        if m_parts:
            lines.append(f"- 메트릭: {' · '.join(m_parts)}")
        raw_issues = sd.get("issues")
        issues = raw_issues if isinstance(raw_issues, list) else []
        if issues:
            lines.append("- 결론:")
            for iss in issues:
                if not isinstance(iss, dict):
                    continue
                sev = iss.get("severity", "?")
                msg = iss.get("msg", "")
                action = iss.get("action", "")
                line = f"  - [{sev}] {msg}"
                if action:
                    line += f" — 조치: {action}"
                lines.append(line)
        lines.append("")
    return lines


def _health_section(diagnosis: Dict[str, Any]) -> List[str]:
    """네트워크 건강도 + 컴포넌트 점수."""
    raw_health = diagnosis.get("health")
    raw_scores = diagnosis.get("component_scores")
    health = raw_health if isinstance(raw_health, dict) else {}
    scores = raw_scores if isinstance(raw_scores, dict) else {}
    if not health and not scores:
        return []
    lines = ["## 네트워크 건강도", ""]
    if health.get("score") is not None:
        grade = health.get("grade", "")
        lines.append(f"- 전체: **{health['score']}** ({grade})")
    if scores:
        score_strs = " · ".join(f"{k}={v}" for k, v in scores.items())
        lines.append(f"- 컴포넌트 점수: {score_strs}")
    lines.append("")
    return lines


def _ai_review_section(result: Dict[str, Any]) -> List[str]:
    """AI 가설 (있으면 마크다운 그대로 inline)."""
    ai = result.get("ai_review") or ""
    if not isinstance(ai, str) or not ai.strip():
        return []
    lines = ["## AI 가설 (Claude/OpenAI 진단)", ""]
    lines.append(ai.strip())
    lines.append("")
    return lines


def build_report_markdown(result: Dict[str, Any]) -> str:
    """분석 result → 단일 마크다운 문자열.

    소비자: `GET /api/analysis/{id}/report.md` 엔드포인트가 그대로 반환.
    외부 도구(pandoc, typora, gstack `/make-pdf` 등)로 PDF·HTML 변환 가능.
    """
    if not isinstance(result, dict):
        return "# WLAN Pcap 분석 리포트\n\n_분석 결과를 불러올 수 없습니다._\n"
    structured = result.get("structured") or {}
    diagnosis = structured.get("diagnosis") or {}
    if not isinstance(diagnosis, dict):
        diagnosis = {}

    out: List[str] = []
    out.extend(_meta_section(result))
    out.extend(_health_section(diagnosis))
    out.extend(_correlations_section(diagnosis))
    out.extend(_issues_table(diagnosis))
    out.extend(_sta_diags_section(diagnosis))
    out.extend(_ai_review_section(result))

    out.append("---")
    out.append(
        "_본 리포트는 pcap-analyzer가 생성. 외부 도구로 PDF/HTML 변환 가능 "
        "(예: `pandoc report.md -o report.pdf`)._"
    )
    return "\n".join(out)
