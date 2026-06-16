"""분석 결과 → 외부 공유용 마크다운 리포트 직렬화.

사용자가 분석 페이지에서 본 내용(메타데이터, 종합 결론, 단일 진단, STA별
진단, AI 가설)을 단일 마크다운 파일로 export. 외부 도구(pandoc, gstack,
typora 등)로 PDF/HTML로 추가 변환 가능하도록 표준 GFM 사양 준수.

차트(미니차트, 메인 타임라인) 이미지는 미포함 — 인쇄용 뷰(/analysis/{id}/report)와
report.pdf도 같은 텍스트 기반 리포트를 공유한다. 차트가 필요하면 분석
페이지를 브라우저에서 직접 인쇄. SVG/PNG inline은 후속 PR 후보로 남긴다.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..core.models import SUBTYPE_NAMES

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
    "mcs_hotspot": "MCS 핫스팟",
    "signal_cliff": "신호 급강하",
    "legacy_heavy": "Legacy 과다",
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
    pcap_name = _clean_code_span(result.get("pcap_name") or "?")
    lines.append(f"**파일**: `{pcap_name}`")
    overview = (result.get("structured") or {}).get("overview") or {}
    pairs: List[str] = []
    if result.get("analyzed_at"):
        pairs.append(f"분석 시각 `{_clean_code_span(result['analyzed_at'])}`")
    if result.get("tshark_version"):
        pairs.append(f"tshark `{_clean_code_span(result['tshark_version'])}`")
    if overview.get("duration_sec") is not None:
        pairs.append(f"캡처 시간 {overview['duration_sec']}s")
    # int 캐스팅 — JSON 라운드트립으로 문자열이 들어오면 `:,` format이
    # ValueError로 500을 만든다. 실패 시 그 라인만 생략.
    try:
        if overview.get("total_frames") is not None:
            pairs.append(f"프레임 {int(overview['total_frames']):,}건")
    except (TypeError, ValueError):
        pass
    try:
        if result.get("pcap_size"):
            pairs.append(f"크기 {int(result['pcap_size']):,}B")
    except (TypeError, ValueError):
        pass
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
        title = _clean_inline(c.get("title", "?"))
        sta = _clean_code_span(c.get("sta_name") or c.get("sta_mac") or "?")
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
        explanation = _clean_inline((c.get("explanation") or "").strip())
        if explanation:
            lines.append(f"- 단일 결론 요약: {explanation}")
        lines.append("")
    return lines


def _clean_cell(s: Any) -> str:
    """GFM 표 셀에 안전한 문자열로 정규화.

    `|`는 셀 구분자라 row를 깨고, 줄바꿈은 row를 두 row로 분할해 표 layout
    을 망가뜨린다. 두 문자 모두 escape/공백 치환. 비문자열 입력은 str() 캐스팅.
    """
    if not isinstance(s, str):
        s = "" if s is None else str(s)
    return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _clean_inline(s: Any) -> str:
    """heading/list 줄에 안전한 inline 텍스트.

    \\n/\\r을 공백으로 치환 — heading(`### Title`) 안에 줄바꿈이 있으면 그 뒤
    줄이 spurious heading이나 새 paragraph로 흘러 마크다운 구조가 깨진다.
    list item(`- explanation`)도 마찬가지로 새 줄에서 indentation 깨짐.
    """
    if not isinstance(s, str):
        s = "" if s is None else str(s)
    return s.replace("\r", " ").replace("\n", " ")


def _clean_code_span(s: Any) -> str:
    """마크다운 backtick code span 내부에 들어갈 값에서 backtick 자체 제거.

    pcap_name·mac·sta 등 외부 입력 문자열이 backtick을 포함하면 ``code``
    span이 중간에 끊겨 rendering이 깨진다. 단순 제거가 가장 안전(이런 값에
    backtick이 들어오는 정상 케이스는 사실상 없음).
    """
    if not isinstance(s, str):
        s = "" if s is None else str(s)
    return s.replace("`", "")


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
        sev = _clean_cell(iss.get("severity", "?"))
        cat = _clean_cell(iss.get("category", iss.get("type", "?")))
        msg = _clean_cell(iss.get("msg") or "")
        action = _clean_cell(iss.get("action") or iss.get("recommendation") or "")
        lines.append(f"| {sev} | {cat} | {msg} | {action} |")
    lines.append("")
    return lines


def _sta_diags_section(
    diagnosis: Dict[str, Any], structured: Dict[str, Any] = None
) -> List[str]:
    """STA별 진단 상세. structured가 주어지면 signal_cliffs(신호 급락)도 합류."""
    sta_diags = diagnosis.get("sta_diags") or []
    if not isinstance(sta_diags, list) or not sta_diags:
        return []
    raw_cliffs = (structured or {}).get("signal_cliffs")
    cliffs_map = raw_cliffs if isinstance(raw_cliffs, dict) else {}
    lines = ["## STA별 진단", ""]
    for sd in sta_diags:
        if not isinstance(sd, dict):
            continue
        name = _clean_inline(sd.get("name", "?"))
        mac = _clean_code_span(sd.get("mac", ""))
        score = sd.get("score")
        lines.append(f"### {name} `{mac}`")
        if score is not None:
            lines.append(f"- 점수: **{score}**/100")
        # 정규화 세부 점수(0-100) — 어느 축이 종합 점수를 끌어내렸는지(화면 miniBar와 동일).
        raw_scores = sd.get("scores")
        scores = raw_scores if isinstance(raw_scores, dict) else {}
        sc_parts = []
        for k, label in (("retry", "Retry"), ("rssi", "RSSI"), ("roaming", "로밍")):
            v = scores.get(k)
            if v is not None:
                sc_parts.append(f"{label} {v}")
        if sc_parts:
            lines.append(f"- 세부 점수: {' · '.join(sc_parts)}")
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
        # 신호 급락(cliff) — 타임라인에만 있던 RSSI 급강하 이벤트를 리포트에 노출.
        cd = cliffs_map.get(sd.get("name"))
        cliff_list = cd.get("cliffs") if isinstance(cd, dict) else None
        if isinstance(cliff_list, list) and cliff_list:
            max_drop = max(
                (c.get("drop_db", 0) for c in cliff_list if isinstance(c, dict)),
                default=0,
            )
            lines.append(f"- 신호 급락: {len(cliff_list)}회 (최대 {max_drop}dB)")
        raw_issues = sd.get("issues")
        issues = raw_issues if isinstance(raw_issues, list) else []
        if issues:
            lines.append("- 결론:")
            for iss in issues:
                if not isinstance(iss, dict):
                    continue
                sev = _clean_inline(iss.get("severity", "?"))
                msg = _clean_inline(iss.get("msg", ""))
                action = _clean_inline(iss.get("action", ""))
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
        # key/value 모두 inline-safe 처리 — 외부 데이터가 |/newline 포함 가능.
        score_strs = " · ".join(
            f"{_clean_inline(k)}={_clean_inline(v)}" for k, v in scores.items()
        )
        lines.append(f"- 컴포넌트 점수: {score_strs}")
    # 요약 지표 — 점수 산출의 원천값을 임계 초과 여부와 무관하게 항상 노출.
    raw_summary = diagnosis.get("summary")
    summary = raw_summary if isinstance(raw_summary, dict) else {}
    if summary:
        s_parts = []
        if summary.get("retry_pct") is not None:
            s_parts.append(f"전체 Retry {summary['retry_pct']}%")
        if summary.get("loss_pct") is not None:
            s_parts.append(f"Ping Loss {summary['loss_pct']}%")
        rt, rs = summary.get("roaming_total"), summary.get("roaming_slow")
        if rt is not None:
            s_parts.append(
                f"로밍 {rt}회" + (f"(느린 {rs})" if rs is not None else "")
            )
        if summary.get("delay_zones") is not None:
            s_parts.append(f"지연구간 {summary['delay_zones']}건")
        if summary.get("anomaly_count") is not None:
            s_parts.append(f"이상프레임 {summary['anomaly_count']}건")
        if s_parts:
            lines.append(f"- 요약: {' · '.join(s_parts)}")
    lines.append("")
    return lines


def _ai_review_section(result: Dict[str, Any]) -> List[str]:
    """AI 가설 (있으면 마크다운 그대로 inline).

    **Trust boundary**: ai_review 본문은 사용자 본인이 호출한 LLM 응답이라
    사용자 input과 동등한 trust level로 취급. 마크다운/raw HTML 콘텐츠가
    pandoc/typora 변환 시 survive할 수 있어 prompt-injection 노출 발생
    가능성 있음. 본 도구는 자동차 WiFi 디버깅 환경(사용자 = 분석가) 가정이라
    raw 그대로 노출하는 게 디버깅 가치 우선. 외부에 PDF 배포 전에는 사용자가
    AI 응답을 검토하는 흐름을 권장.
    """
    ai = result.get("ai_review") or ""
    if not isinstance(ai, str) or not ai.strip():
        return []
    lines = ["## AI 가설 (Claude/OpenAI 진단)", ""]
    lines.append(ai.strip())
    lines.append("")
    return lines


def _devices_section(structured: Dict[str, Any]) -> List[str]:
    """감지된 디바이스 표(이름/MAC/역할/프레임수/대표 IP) + 프로토콜·서브타입 분포."""
    overview = structured.get("overview") or {}
    devices = overview.get("devices") or []
    proto = overview.get("protocol_dist") or {}
    subtype = overview.get("subtype_dist") or {}
    has_dev = isinstance(devices, list) and devices
    if not has_dev and not proto and not subtype:
        return []
    lines = ["## 디바이스 / 프레임 분포", ""]
    if has_dev:
        lines.append("| 이름 | MAC | 역할 | 프레임수 | 대표 IP |")
        lines.append("|---|---|---|---|---|")
        for d in devices:
            if not isinstance(d, dict):
                continue
            name = _clean_cell(d.get("name", "?"))
            mac = _clean_cell(d.get("mac", ""))
            role = _clean_cell(d.get("role", ""))
            try:
                cnt = f"{int(d.get('count', 0)):,}"
            except (TypeError, ValueError):
                cnt = _clean_cell(d.get("count", ""))
            ips = d.get("ips") if isinstance(d.get("ips"), list) else []
            ip_str = ""
            if ips:
                ip_str = _clean_cell(ips[0])
                if len(ips) > 1:
                    ip_str += f" (+{len(ips) - 1})"
            lines.append(f"| {name} | {mac} | {role} | {cnt} | {ip_str} |")
        lines.append("")
    if isinstance(proto, dict) and proto:
        top = sorted(proto.items(), key=lambda kv: -kv[1])[:8]
        lines.append(
            "- 프로토콜 분포: "
            + ", ".join(f"{_clean_inline(k)} {v:,}" for k, v in top)
        )
    if isinstance(subtype, dict) and subtype:
        top = sorted(subtype.items(), key=lambda kv: -kv[1])[:8]
        lines.append(
            "- 서브타입 분포: "
            + ", ".join(
                f"{_clean_inline(SUBTYPE_NAMES.get(k, k))} {v:,}" for k, v in top
            )
        )
    if (isinstance(proto, dict) and proto) or (isinstance(subtype, dict) and subtype):
        lines.append("")
    return lines


def _ping_section(structured: Dict[str, Any]) -> List[str]:
    """Ping/RTT 요약(응답수·Loss·평균·P95). 단방향 캡처는 avg/p95가 None이라 생략."""
    ping = structured.get("ping") or {}
    stats = ping.get("stats")
    if not isinstance(stats, dict) or not stats:
        return []
    parts = []
    if stats.get("count") is not None:
        parts.append(f"응답 {stats['count']:,}")
    if stats.get("loss_pct") is not None:
        lc = stats.get("loss_count")
        suffix = f"({lc:,})" if isinstance(lc, int) else ""
        parts.append(f"Loss {stats['loss_pct']}%{suffix}")
    if stats.get("avg") is not None:
        parts.append(f"평균 RTT {stats['avg']}ms")
    if stats.get("p95") is not None:
        parts.append(f"P95 RTT {stats['p95']}ms")
    if not parts:
        return []
    return ["## Ping / RTT", "", f"- {' · '.join(parts)}", ""]


def _device_phy_section(structured: Dict[str, Any]) -> List[str]:
    """네트워크 전체 PHY 분포 + PHY/MCS별 retry 핫스팟 표(표본>=30).

    장치별 탭의 핵심 시각(PHY 모드 분포, MCS별 retry%)을 리포트로 직렬화.
    UI(charts.js)와 동일하게 표본<30 MCS는 통계적으로 불안정하므로 제외한다.
    """
    system_stats = structured.get("system_stats")
    if not isinstance(system_stats, dict) or not system_stats:
        return []
    lines = ["## 네트워크 PHY / MCS", ""]
    phy_summary = system_stats.get("phy_summary")
    if isinstance(phy_summary, dict) and phy_summary:
        ordered = sorted(phy_summary.items(), key=lambda kv: -kv[1])
        lines.append(
            "- PHY 송신 분포: "
            + ", ".join(f"{_clean_inline(k)} {v:,}" for k, v in ordered)
        )
    MIN_SAMPLE = 30
    rows = []
    mrp = system_stats.get("mcs_retry_by_phy")
    if isinstance(mrp, dict):
        for phy, mcs_map in mrp.items():
            if not isinstance(mcs_map, dict):
                continue
            for mcs_key, r in mcs_map.items():
                if isinstance(r, dict) and (r.get("total", 0) or 0) >= MIN_SAMPLE:
                    rows.append((phy, mcs_key, r))
    rows.sort(key=lambda x: -(x[2].get("retry_pct", 0) or 0))
    if rows:
        lines.append("")
        lines.append(f"표본 ≥{MIN_SAMPLE} MCS의 retry (retry% 내림차순):")
        lines.append("")
        lines.append("| PHY | MCS | 전체 | Retry | Retry% |")
        lines.append("|---|---|---|---|---|")
        for phy, mcs_key, r in rows[:15]:
            label = (
                f"{mcs_key}Mbps" if phy == "Legacy" else f"MCS{mcs_key}"
            )
            lines.append(
                f"| {_clean_cell(phy)} | {_clean_cell(label)} | "
                f"{r.get('total', 0):,} | {r.get('retry', 0):,} | "
                f"{r.get('retry_pct', 0)}% |"
            )
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
    out.extend(_devices_section(structured))
    out.extend(_health_section(diagnosis))
    out.extend(_ping_section(structured))
    out.extend(_correlations_section(diagnosis))
    out.extend(_issues_table(diagnosis))
    out.extend(_sta_diags_section(diagnosis, structured))
    out.extend(_device_phy_section(structured))
    out.extend(_ai_review_section(result))

    out.append("---")
    out.append(
        "_본 리포트는 pcap-analyzer가 생성. 외부 도구로 PDF/HTML 변환 가능 "
        "(예: `pandoc report.md -o report.pdf`)._"
    )
    return "\n".join(out)
