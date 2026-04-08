"""분석 결과를 텍스트 리포트로 포맷팅한다."""
import time
from typing import List
from .models import AnalysisSection

# brief 모드에서 전체 출력할 섹션 키워드
BRIEF_FULL_SECTIONS = ["진단", "Loss", "로밍 영향", "AP 비교", "외부 로그"]


def format_report(
    sections: List[AnalysisSection],
    pcap_path: str,
    wpa_used: bool = False,
    brief: bool = False,
) -> str:
    out = []
    width = 80

    out.append("=" * width)
    title = "WLAN Pcap 종합 분석 리포트"
    if brief:
        title += " (간결 모드)"
    out.append(title)
    out.append("=" * width)
    out.append(f"입력 파일: {pcap_path}")
    out.append(f"생성 시각: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    out.append(f"WPA 복호화: {'사용' if wpa_used else '미사용'}")
    out.append("")

    out.append("--- 요약 ---")
    for sec in sections:
        out.append(f"  [{sec.title}] {sec.summary}")
    out.append("")

    if brief:
        for sec in sections:
            if any(kw in sec.title for kw in BRIEF_FULL_SECTIONS):
                out.append("=" * width)
                out.append(sec.title)
                out.append("=" * width)
                out.extend(sec.lines)
                out.append("")
    else:
        for sec in sections:
            out.append("=" * width)
            out.append(sec.title)
            out.append("=" * width)
            out.extend(sec.lines)
            out.append("")

    return "\n".join(out)
