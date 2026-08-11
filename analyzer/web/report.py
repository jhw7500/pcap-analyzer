"""분석 결과 → 외부 공유용 마크다운 리포트 직렬화.

사용자가 분석 페이지에서 본 내용(메타데이터, 종합 결론, 단일 진단, STA별
진단, AI 가설)을 단일 마크다운 파일로 export. 외부 도구(pandoc, gstack,
typora 등)로 PDF/HTML로 추가 변환 가능하도록 표준 GFM 사양 준수.

차트(미니차트, 메인 타임라인) 이미지는 미포함 — 인쇄용 뷰(/analysis/{id}/report)와
report.pdf도 같은 텍스트 기반 리포트를 공유한다. 차트가 필요하면 분석
페이지를 브라우저에서 직접 인쇄. SVG/PNG inline은 후속 PR 후보로 남긴다.
"""
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..core.models import SUBTYPE_NAMES
# 손실 판정 근거 라벨은 structured가 단일 정의 — 리포트·화면이 같은 어휘를 쓴다.
from .structured import LOSS_BASIS_LABELS, LOSS_BASIS_WIRED

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
        at = _clean_code_span(result["analyzed_at"])
        # 시간대 표기: 신규 pipeline은 '%Z'(예: KST)를 포함한다. 시간대가 없는
        # 구버전 값은 분석 호스트 로컬 시각이므로 라벨을 붙여 _format_epoch의
        # UTC 고정 정책(위 docstring)과 혼동되지 않게 한다.
        has_tz = bool(re.search(r"(?:[A-Za-z]{2,5}|[+-]\d{2}:?\d{2})\s*$", at))
        suffix = "" if has_tz else " (호스트 로컬 시각)"
        pairs.append(f"분석 시각 `{at}`{suffix}")
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
    # 평균/피크 throughput — per_second.bytes(신규 필드) 기반. 구버전 result엔
    # bytes가 없어 라인 자체를 생략한다.
    tp = _throughput_stats((result.get("structured") or {}).get("per_second"))
    if tp:
        lines.append(
            f"처리량: 평균 {tp['avg_mbps']} Mbps · 피크 {tp['peak_mbps']} Mbps"
        )
    lines.append("")
    return lines


def _throughput_stats(per_second: Any) -> Dict[str, Any]:
    """per_second.timeline의 bytes로 평균/피크 Mbps 계산. bytes 없으면 {}."""
    if not isinstance(per_second, dict):
        return {}
    timeline = per_second.get("timeline")
    if not isinstance(timeline, list) or not timeline:
        return {}
    entries = [
        e for e in timeline
        if isinstance(e, dict) and isinstance(e.get("bytes"), (int, float))
    ]
    if not entries:
        return {}
    byte_vals = [e["bytes"] for e in entries]
    total = sum(byte_vals)
    # duration은 epoch 경과 시간 기준 — zero-fill timeline에서는 len(entries)와
    # 동일하지만(정상 캡처 출력 불변), 희소 폴백 timeline(6h+ span)에서는 관측
    # entry 수로 나누면 평균이 부풀려진다(PR #27 Codex P2). epoch이 없는
    # 구버전 entry가 섞이면 기존 방식(len)으로 폴백.
    epochs = [e.get("epoch") for e in entries]
    # span 산술 전체를 try로 감싼다 — 개별 값 검증(isinstance/isfinite)으로는
    # 이형 입력을 다 못 막는다: None 비교 TypeError, NaN 전파, ±1e308 차→inf,
    # 초대형 int는 math.isfinite 자체가 OverflowError (PR #27 리뷰 3R·4R).
    # 어떤 실패든 entry 수 폴백(zero-fill 가정) — 크래시 대신 보수적 값.
    try:
        # float NaN/Inf는 사전 차단 — max/min은 NaN 위치에 따라 조용히 잘못된
        # 값을 남긴다(꼬리 NaN이면 span 0 → 과대계상, PR #27 리뷰 4R). int는
        # 크기 무관 정확 산술이라 통과시킨다(초대형 int도 올바른 span — 4R 테스트).
        if any(isinstance(x, float) and (x != x or math.isinf(x)) for x in epochs):
            raise ValueError
        span = max(epochs) - min(epochs)
        duration = int(span) + 1 if math.isfinite(float(span)) else len(entries)
    except (TypeError, ValueError, OverflowError):
        duration = len(entries)
    return {
        "avg_mbps": round(total * 8 / 1e6 / duration, 2) if duration else 0.0,
        "peak_mbps": round(max(byte_vals) * 8 / 1e6, 2),
    }


def _summary_section(diagnosis: Dict[str, Any]) -> List[str]:
    """최상단 Executive Summary — 판정·최상위 문제·측정 불가 항목을 두괄식으로.

    diagnosis.health.score가 없는 구버전 result에는 섹션 자체를 생략해
    하위호환을 유지한다(웹 UI/report 모두 새 키는 조건부 렌더 원칙).
    """
    raw_health = diagnosis.get("health")
    health = raw_health if isinstance(raw_health, dict) else {}
    if health.get("score") is None:
        return []
    raw_issues = diagnosis.get("issues")
    issues = (
        [i for i in raw_issues if isinstance(i, dict)]
        if isinstance(raw_issues, list) else []
    )
    lines = ["## 요약", ""]
    grade = _clean_inline(health.get("grade", ""))
    verdict = f"**건강도 {health['score']}/100 ({grade})**"
    severity_order = {"high": 0, "medium": 1, "low": 2}
    if issues:
        sev_counts: Dict[str, int] = {}
        for iss in issues:
            sev = iss.get("severity", "?")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cnt_str = " · ".join(
            f"{_clean_inline(sev)} {n}건"
            for sev, n in sorted(
                sev_counts.items(), key=lambda kv: severity_order.get(kv[0], 3)
            )
        )
        lines.append(f"{verdict} — 이슈 {len(issues)}건 ({cnt_str})")
        lines.append("")
        lines.append("최상위 문제:")
        top = sorted(
            issues, key=lambda i: severity_order.get(i.get("severity"), 3)
        )[:3]
        for iss in top:
            sev = _clean_inline(iss.get("severity", "?"))
            cat = _clean_inline(iss.get("category", iss.get("type", "?")))
            msg = _clean_inline(iss.get("msg") or "")
            action = _clean_inline(
                iss.get("action") or iss.get("recommendation") or ""
            )
            line = f"- [{sev}] {cat}: {msg}"
            if action:
                line += f" — 조치: {action}"
            lines.append(line)
    else:
        lines.append(f"{verdict} — 중대 문제 없음")
    # 측정 불가 컴포넌트(None) 명시 — 점수에서 빠진 축을 요약에서 바로 알림.
    raw_scores = diagnosis.get("component_scores")
    scores = raw_scores if isinstance(raw_scores, dict) else {}
    unmeasured = [k for k, v in scores.items() if v is None]
    if unmeasured:
        labels = [
            "Ping Loss (ICMP 트래픽 없음)" if k == "loss" else _clean_inline(k)
            for k in unmeasured
        ]
        lines.append(f"- 측정 불가: {', '.join(labels)}")
    lines.append("")
    return lines


def _evidence_str(issue: Dict[str, Any]) -> str:
    """issue의 frame_refs[:5] + time_window → 근거 문자열.

    `frame.number in {446,447,...}`는 Wireshark 디스플레이 필터로 그대로 복붙
    가능한 형태. frame_refs가 없으면(비정상/구버전) '-' 반환.
    """
    refs = issue.get("frame_refs")
    if not isinstance(refs, list) or not refs:
        return "-"
    head = ",".join(str(r) for r in refs[:5])
    s = f"`frame.number in {{{head}}}`"
    if len(refs) > 5:
        s += f" 외 {len(refs) - 5:,}건"
    tw = issue.get("time_window")
    if isinstance(tw, dict):
        s_str = _format_epoch(tw.get("start_epoch"))
        e_str = _format_epoch(tw.get("end_epoch"))
        if s_str and e_str:
            s += f" · {s_str} ~ {e_str}"
    return s


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
    lines.append("| Severity | Category | 문제 | 조치 | 근거 |")
    lines.append("|---|---|---|---|---|")
    for iss in issues:
        if not isinstance(iss, dict):
            continue
        sev = _clean_cell(iss.get("severity", "?"))
        cat = _clean_cell(iss.get("category", iss.get("type", "?")))
        msg = _clean_cell(iss.get("msg") or "")
        action = _clean_cell(iss.get("action") or iss.get("recommendation") or "")
        # 근거: 대표 frame # + 시간 구간 — Wireshark 필터 복붙 가능 형태.
        evidence = _evidence_str(iss)
        lines.append(f"| {sev} | {cat} | {msg} | {action} | {evidence} |")
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
        # 단위 병기 — 'Retry 18.3'처럼 단위 없는 수치는 %인지 건수인지 모호.
        for k, label, unit in (
            ("retry_pct", "Retry", "%"),
            ("rssi_avg", "RSSI 평균", "dBm"),
            ("rssi_min", "RSSI 최저", "dBm"),
            ("roaming_count", "로밍", "회"),
            ("slow_roaming", "느린 로밍", "회"),
            ("total_frames", "프레임", "건"),
        ):
            v = metrics.get(k)
            if v is not None:
                m_parts.append(f"{label} {v}{unit}")
                # "느린 로밍 0회"는 판정 자체가 안 된 경우에도 정상처럼 읽힌다 —
                # 실제 분모(판정된 로밍 수)를 바로 옆에 병기한다.
                if k == "slow_roaming":
                    total_r = metrics.get("roaming_count")
                    meas = metrics.get("roaming_measurable")
                    if isinstance(meas, int) and isinstance(total_r, int) and meas < total_r:
                        m_parts[-1] += f" (판정 {meas}/{total_r}회)"
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
                # 근거: 대표 frame # + 시간 구간 (없으면 줄 자체 생략).
                evidence = _evidence_str(iss)
                if evidence != "-":
                    lines.append(f"    - 근거: {evidence}")
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
        # None = 측정 불가 컴포넌트(예: ICMP 없는 캡처의 loss).
        score_strs = " · ".join(
            f"{_clean_inline(k)}={'측정 불가' if v is None else _clean_inline(v)}"
            for k, v in scores.items()
        )
        lines.append(f"- 컴포넌트 점수: {score_strs}")
    if "loss" in scores and scores.get("loss") is None:
        lines.append("- Ping: 측정 불가 — ICMP 트래픽 없음")
    # 요약 지표 — 점수 산출의 원천값을 임계 초과 여부와 무관하게 항상 노출.
    raw_summary = diagnosis.get("summary")
    summary = raw_summary if isinstance(raw_summary, dict) else {}
    if summary:
        s_parts = []
        if summary.get("retry_pct") is not None:
            s_parts.append(f"전체 Retry {summary['retry_pct']}%")
        # 판정에 쓴 값을 먼저 쓰고, 유선 확정이면 무선 관측값을 괄호로 병기한다 —
        # 두 값이 다른 건 캡처 커버리지 정보라 감추지 않는다(실측 유선 0.38% vs
        # 무선 8.24%). 구버전 result에는 loss_pct_used가 없어 기존 키로 폴백한다.
        used = summary.get("loss_pct_used")
        basis = summary.get("loss_basis")
        observed = summary.get("loss_pct")
        if used is None and basis is None:
            used = observed          # 구버전 result
        if used is not None:
            # 키 출처: structured.LOSS_BASIS_WIRED / LOSS_BASIS_WIRELESS.
            label = LOSS_BASIS_LABELS.get(basis, "")
            part = f"Ping Loss {used}%" + (f" ({label})" if label else "")
            if (basis == LOSS_BASIS_WIRED
                    and isinstance(observed, (int, float)) and observed != used):
                part += f" / 무선 관측 {observed}%"
            s_parts.append(part)
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
    # 채널/밴드 — overview.channels(신규 키). 구버전 result엔 없어 생략.
    channels = overview.get("channels") if isinstance(overview, dict) else None
    if isinstance(channels, dict):
        by_channel = channels.get("by_channel")
        if isinstance(by_channel, list) and by_channel:
            ch_parts = []
            for c in by_channel[:5]:
                if not isinstance(c, dict):
                    continue
                ch = c.get("channel")
                band = c.get("band") or "-"
                ch_parts.append(
                    f"CH{ch if ch is not None else '?'}({band}) "
                    f"{_fmt_count(c.get('frames'))}"
                )
            if ch_parts:
                lines.append(f"- 채널 분포: {', '.join(ch_parts)}")
        ap_channels = channels.get("ap_channels")
        if isinstance(ap_channels, dict) and ap_channels:
            ap_parts = [
                f"{_clean_inline(a.get('name', '?'))} CH{a.get('channel', '?')}"
                f"({a.get('band') or '-'})"
                for a in ap_channels.values()
                if isinstance(a, dict)
            ]
            if ap_parts:
                lines.append(f"- AP 채널(beacon 기준): {', '.join(ap_parts)}")
    if (isinstance(proto, dict) and proto) or (isinstance(subtype, dict) and subtype) \
            or isinstance(channels, dict):
        lines.append("")
    return lines


def _fmt_count(v: Any) -> str:
    """정수 카운트 포맷 — 비정수(직렬화 잔재)면 그대로 문자열."""
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return str(v)


def _roaming_section(structured: Dict[str, Any]) -> List[str]:
    """로밍 시퀀스 표 — Gap/4-way(ms)/밴드 전환 포함(신규 키는 .get() 가드)."""
    roaming = structured.get("roaming") or {}
    seqs = roaming.get("sequences") if isinstance(roaming, dict) else None
    if not isinstance(seqs, list) or not seqs:
        return []
    lines = ["## 로밍 (BSS Transition)", ""]
    # Gap은 Auth→Reassoc 구간만이라 로밍 전체 소요와 다르다 — 둘 다 싣는다.
    lines.append(
        "| # | 시각(Auth) | STA | AP (이전→이후) | Gap(ms) | 4-way(ms) | 전체(ms) | 밴드 전환 |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, s in enumerate(seqs[:20], start=1):
        if not isinstance(s, dict):
            continue
        # 측정 불가면 auth_epoch이 없다 — Assoc 시각으로 대체해 행이 "?"가 되지 않게.
        ts = _format_epoch(s.get("auth_epoch")) or _format_epoch(s.get("assoc_epoch")) or "?"
        sta = _clean_cell(s.get("sta_name") or s.get("sta") or "?")
        ap_to = _clean_cell(s.get("ap_name") or s.get("ap") or "?")
        prev = s.get("prev_ap_name") or ""
        ap_str = f"{_clean_cell(prev)} → {ap_to}" if prev else ap_to
        gap = s.get("gap_ms")
        if isinstance(gap, (int, float)):
            gap_str = f"{gap}"
            # AP 응답 기준으로 잰 하한값이면 그 사실을 숨기지 않는다.
            if s.get("gap_basis") == "auth_response":
                gap_str += " (하한)"
        else:
            # 무엇이 없어서 못 쟀는지 함께 적는다 — "-"만 두면 지연이 없었던 것처럼 읽힌다.
            missing = s.get("missing_labels") or []
            miss_str = ", ".join(str(m) for m in missing) if missing else "Auth 프레임"
            gap_str = f"측정불가 ({miss_str} 미포착)"
        fw = s.get("four_way_ms")
        fw_str = f"{fw}" if isinstance(fw, (int, float)) else "-"
        bc = s.get("band_change")
        if bc is True:
            bc_str = f"{s.get('prev_ap_band') or '?'}→{s.get('ap_band') or '?'}"
        elif bc is False:
            bc_str = "동일"
        else:
            bc_str = "-"
        total = s.get("total_roam_ms")
        total_str = f"{total}" if isinstance(total, (int, float)) else "-"
        lines.append(
            f"| {i} | {ts} | {sta} | {ap_str} | {gap_str} | {fw_str} | {total_str} | {bc_str} |"
        )
    lines.append("")
    lines.append(
        "> Gap = Auth 요청 → Reassoc 요청 구간만. 전체 = Auth 요청 → 4-way 완료 "
        "(로밍 실소요). **느린 로밍 판정은 전체 기준**이다. 4-way를 못 찾으면 전체는 "
        "`-`이고, 그때는 Gap이 이미 임계를 넘은 경우에만 느림으로 확정한다"
        "(전체 ≥ Gap 이므로)."
    )
    if len(seqs) > 20:
        lines.append("")
        lines.append(f"_(총 {len(seqs)}건 중 앞 20건만 표시)_")
    lines.append("")
    return lines


def _ping_section(structured: Dict[str, Any]) -> List[str]:
    """Ping/RTT 요약(응답수·Loss·평균·P95). 단방향 캡처는 avg/p95가 None이라 생략."""
    ping = structured.get("ping") or {}
    # 유선 확정 블록(스펙 2026-08-05-wired-rtt-primary §4) — GT 있으면 서두에.
    # (측정 불가 분기 앞에서 계산해야 ICMP 없는 경우에도 GT가 손실되지 않음)
    gt = ping.get("ground_truth") or {}
    gt_lines: List[str] = []
    if isinstance(gt, dict) and isinstance(gt.get("total"), int) and gt["total"] > 0:
        gparts = [f"요청 {gt['total']:,}",
                  f"손실 {gt.get('ng', 0):,}건 ({gt.get('loss_pct', 0.0)}%)"]
        rs = gt.get("rtt_stats")
        if isinstance(rs, dict):
            gparts.append(f"평균 RTT {rs['avg_ms']}ms")
            gparts.append(f"P95 RTT {rs['p95_ms']}ms")
        gt_lines.append(f"- **유선 확정**: {' · '.join(gparts)}")
        streaks = gt.get("streaks") or []
        if streaks:
            worst = max(streaks, key=lambda s: s.get("count", 0))
            gt_lines.append(
                f"- 유선 손실 구간 {len(streaks)}곳 — 최장 {worst.get('count', 0)}건"
                f"/{worst.get('duration_sec', 0)}초 ({_clean_inline(str(worst.get('target', '?')))})"
            )
    # 측정 불가(ICMP 없음) 캡처 — '응답 0 · Loss 0%'는 무결점으로 오독되므로 N/A 명시
    comp = (structured.get("diagnosis") or {}).get("component_scores") or {}
    if "loss" in comp and comp.get("loss") is None:
        na_line = "- 측정 불가 — ICMP 트래픽 없음 (RTT/Loss 평가 대상 아님)"
        if gt_lines:
            return ["## Ping / RTT", ""] + gt_lines + [
                "- 무선 관측 (보조지표): 측정 불가 — ICMP 트래픽 없음", ""]
        return ["## Ping / RTT", "", na_line, ""]
    stats = ping.get("stats")
    if not isinstance(stats, dict) or not stats:
        return ["## Ping / RTT", ""] + gt_lines + [""] if gt_lines else []
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
        return ["## Ping / RTT", ""] + gt_lines + [""] if gt_lines else []
    # GT 있으면: 유선 줄 + 무선 줄(보조지표 라벨). GT 없으면: 기존 경로(byte-identical)
    if gt_lines:
        wireless_line = f"- 무선 관측 (보조지표): {' · '.join(parts)}"
        return ["## Ping / RTT", ""] + gt_lines + [wireless_line, ""]
    return ["## Ping / RTT", "", f"- {' · '.join(parts)}", ""]


def _multi_wireless_section(structured: Dict[str, Any]) -> List[str]:
    """다중 무선 병합 요약 — structured["merge"]가 있을 때만 (단일 무선 report
    출력 불변, 백로그 ④: Phase 2부터 report에 병합 맥락이 통째로 빠져 있었다)."""
    merge = structured.get("merge")
    if not isinstance(merge, dict) or not merge:
        return []
    lines = ["## 다중 무선 병합", ""]
    for s in structured.get("sources") or []:
        if not isinstance(s, dict) or s.get("role") != "wireless":
            continue
        parts = [f"{s.get('frame_count') or 0:,} 프레임"]
        off = s.get("applied_offset_ms")
        if isinstance(off, (int, float)):
            method = s.get("offset_method") or ""
            parts.append("기준 시계" if method == "reference"
                         else f"오프셋 {off:+,.3f}ms ({_clean_inline(str(method))})")
        tag = s.get("tag")
        prefix = f"{_clean_inline(str(tag))} " if tag else ""
        # 파일명은 backtick code span 내부라 _clean_code_span — _meta_section의
        # pcap_name과 동일 관례 (백틱 포함 외부 입력이 span을 깨는 것 방지).
        lines.append(f"- {prefix}`{_clean_code_span(s.get('name', '?'))}` — {' · '.join(parts)}")
    kept = merge.get("kept") or 0
    cov = merge.get("coverage") or {}

    def _pct(n: int) -> str:
        return f"{100 * n / kept:.1f}%" if kept else "0%"

    cov_parts = [f"2개 이상 포착 {cov.get('both', 0):,}건({_pct(cov.get('both', 0))})"]
    for t, n in (cov.get("only") or {}).items():
        if not isinstance(n, (int, float)):
            continue  # 직렬화 외부 데이터 방어 — None 등이면 항목 생략 (PR #27 5R)
        cov_parts.append(f"{_clean_inline(str(t))} 단독 {n:,}건({_pct(n)})")
    lines.append(f"- 병합: 중복 제거 {merge.get('duplicates') or 0:,}건 · "
                 f"통합 {kept:,}건 — {' · '.join(cov_parts)}")
    lines.append("")
    return lines


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
    out.extend(_multi_wireless_section(structured))
    # 두괄식 — 판정/최상위 문제를 제목 바로 아래에서 먼저 보여준다.
    out.extend(_summary_section(diagnosis))
    out.extend(_devices_section(structured))
    out.extend(_health_section(diagnosis))
    out.extend(_ping_section(structured))
    out.extend(_roaming_section(structured))
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
