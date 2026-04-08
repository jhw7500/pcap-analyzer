"""외부 로그 파일을 타임스탬프 기반으로 분석 리포트에 병합한다."""
import re
from typing import List, Dict, Optional
from .models import AnalysisSection

TIMESTAMP_PATTERNS = [
    (re.compile(r'^(\d{10}\.\d+):?\s+(.*)'), "epoch"),
    (re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.*)'), "syslog"),
    (re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d+:\d+:\d+[\.\d]*)\s+(.*)'), "iso"),
    (re.compile(r'^(\d+:\d+:\d+[\.\d]*)\s+(.*)'), "time"),
]

KEYWORDS = ["ROAM", "roam", "AUTH", "auth", "ASSOC", "assoc",
            "EAPOL", "eapol", "DISCONNECT", "disconnect",
            "SCAN", "scan", "CONNECT", "connect",
            "carrier", "link", "signal", "rssi", "RSSI",
            "4-Way", "4way", "handshake", "deauth", "DEAUTH"]


def _parse_log_line(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line:
        return None
    for pattern, fmt in TIMESTAMP_PATTERNS:
        m = pattern.match(line)
        if m:
            return {"timestamp": m.group(1), "message": m.group(2), "format": fmt}
    return None


def merge_logs(log_paths: List[str]) -> AnalysisSection:
    lines = []
    all_entries = []

    for path in log_paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                log_lines = f.readlines()
        except OSError as e:
            lines.append(f"[ERROR] {path}: {e}")
            continue

        fname = path.rsplit("/", 1)[-1]
        parsed = 0
        for line in log_lines:
            entry = _parse_log_line(line)
            if entry:
                entry["source"] = fname
                all_entries.append(entry)
                parsed += 1
        lines.append(f"  {fname}: {parsed}/{len(log_lines)} 라인 파싱")

    if not all_entries:
        return AnalysisSection(
            title="외부 로그", lines=["파싱 가능한 로그 없음"], summary="로그 없음")

    filtered = [e for e in all_entries
                if any(kw in e["message"] for kw in KEYWORDS)]

    lines.append(f"\n로밍/연결 관련 로그: {len(filtered)}건 (전체 {len(all_entries)}건)")
    lines.append("")
    lines.append(f"{'Timestamp':>20} | {'Source':>15} | Message")
    lines.append("-" * 80)

    for e in filtered[:100]:
        lines.append(f"{e['timestamp']:>20} | {e['source']:>15} | {e['message'][:60]}")

    if len(filtered) > 100:
        lines.append(f"  ... 외 {len(filtered) - 100}건 생략")

    summary = f"로그 {len(filtered)}건 (키워드 필터)"
    return AnalysisSection(title="외부 로그 병합", lines=lines, summary=summary)
