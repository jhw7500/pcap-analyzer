"""Sub-AC 3: 종합 진단의 모든 결론이 근거(frame_refs)+time_window를 동반함을 검증.

대표 캡처 fixture로 전체 진단(build_conclusions/analyze)을 실행하고,
grounding-validator(find_ungrounded_conclusions)가 '근거 없는 결론 0건'을
보고하는지 확인한다. 또한 'further investigation needed' 류 punt 표현이
진단 출력 어디에도 남아있지 않음을 함께 검증한다.
"""
from analyzer.core.models import Frame
from analyzer.core.indexer import FrameIndex
from analyzer.core.modules.diagnosis import (
    analyze,
    build_conclusions,
    contains_punt_language,
    find_ungrounded_conclusions,
)

AP = "aa:bb:cc:00:00:01"
STA_A = "aa:bb:cc:00:00:0a"  # 고retry+버스트+저RSSI+로밍+ping loss → 제안 path1
STA_B = "aa:bb:cc:00:00:0b"  # ping loss + 잦은 로밍 (저retry)        → 제안 path2
STA_C = "aa:bb:cc:00:00:0c"  # ping loss + 중간 retry(INFO)           → 제안 path3(구 punt)
STA_D = "aa:bb:cc:00:00:0d"  # 정상

AP_IP = "10.0.0.1"
IP = {STA_A: "10.0.0.10", STA_B: "10.0.0.11", STA_C: "10.0.0.12", STA_D: "10.0.0.13"}

ROLES = {
    AP: {"role": "AP", "name": "AP(0001)", "count": 0},
    STA_A: {"role": "STA", "name": "STA-A", "count": 0},
    STA_B: {"role": "STA", "name": "STA-B", "count": 0},
    STA_C: {"role": "STA", "name": "STA-C", "count": 0},
    STA_D: {"role": "STA", "name": "STA-D", "count": 0},
}

_counter = {"n": 0}


def _num() -> int:
    _counter["n"] += 1
    return _counter["n"]


def mk(**kw) -> Frame:
    defaults = dict(
        number=_num(), epoch=1000.0, timestamp="2026-01-01 00:00:00.000",
        retry=False, subtype="40", protocol="802.11", length=100,
        mcs="7", rssi="-60,-62", ta=AP, ra=AP,
        ip_src="", ip_dst="", icmp_type="", arp_opcode="",
        tcp_len="", tcp_flags="", seq="", icmp_seq="", bssid=AP, icmp_ident="",
    )
    defaults.update(kw)
    return Frame(**defaults)


def _ping_flow(sta: str, ident: str, base_epoch: float):
    """bidirectional ICMP 흐름: req seq 1,2,3 / reply seq 1,3 → seq 2 손실 1건."""
    sta_ip = IP[sta]
    frames = []
    for seq in ("1", "2", "3"):
        frames.append(mk(
            epoch=base_epoch + int(seq), ta=sta, ra=AP,
            ip_src=sta_ip, ip_dst=AP_IP, icmp_type="8",
            icmp_seq=seq, icmp_ident=ident, protocol="ICMP",
        ))
    for seq in ("1", "3"):  # seq 2 reply 누락 → 무선 손실
        frames.append(mk(
            epoch=base_epoch + int(seq) + 0.1, ta=AP, ra=sta,
            ip_src=AP_IP, ip_dst=sta_ip, icmp_type="0",
            icmp_seq=seq, icmp_ident=ident, protocol="ICMP",
        ))
    return frames


def representative_capture():
    """모든 진단 코드 경로를 자극하는 대표 캡처 fixture (frames, roles, index)."""
    frames = []

    # --- STA_A: retry 폭증(>3000/min, 단일 분 버킷) + 저RSSI + ping loss + 로밍 ---
    for i in range(3001):
        frames.append(mk(
            epoch=1980.0 + i * 0.01, ta=STA_A, ra=AP, subtype="40",
            retry=True, rssi="-80,-82",  # rssi_first=-80 < -75
        ))
    for _ in range(4):  # Auth(11) ta=STA_A → auth_count=4 (>3)
        frames.append(mk(epoch=1975.0, ta=STA_A, ra=AP, subtype="11", protocol="802.11"))
    frames += _ping_flow(STA_A, "200", 1990.0)

    # --- STA_B: ping loss + 잦은 로밍(>2), retry 0% ---
    for i in range(40):
        frames.append(mk(epoch=3000.0 + i, ta=STA_B, ra=AP, subtype="40", retry=False))
    for _ in range(4):
        frames.append(mk(epoch=3005.0, ta=STA_B, ra=AP, subtype="11", protocol="802.11"))
    frames += _ping_flow(STA_B, "201", 3010.0)

    # --- STA_C: ping loss + 중간 retry(~26%, INFO) + 로밍 없음 ---
    for i in range(100):
        frames.append(mk(
            epoch=4000.0 + i, ta=STA_C, ra=AP, subtype="40",
            retry=(i < 28),  # 28/105 ≈ 26.7% (>25, <=30)
        ))
    frames += _ping_flow(STA_C, "202", 4200.0)

    # --- STA_D: 정상 (저retry, 양호 RSSI, ping/로밍 없음) ---
    for i in range(20):
        frames.append(mk(epoch=5000.0 + i, ta=STA_D, ra=AP, subtype="40", retry=False))

    index = FrameIndex(frames, ROLES)
    return frames, dict(ROLES), index


class TestEvidenceLinkedDiagnosis:
    def test_full_diagnosis_has_zero_ungrounded_conclusions(self):
        """대표 캡처 전체 진단 → grounding-validator가 근거 없는 결론 0건 보고."""
        frames, roles, index = representative_capture()
        conclusions = build_conclusions(frames, roles, index)

        assert conclusions, "진단 결론이 생성되어야 한다"
        assert find_ungrounded_conclusions(conclusions) == []

        # 모든 결론이 실제 frame.number 근거 + time_window를 동반
        for c in conclusions:
            assert c.frame_refs, f"근거 없는 결론: {c.message!r}"
            assert c.time_window is not None
            assert c.time_window.end_epoch >= c.time_window.start_epoch

    def test_dict_wrapped_output_also_grounded(self):
        """{'conclusions': [...]} 래핑 형태로도 0건 보고."""
        frames, roles, index = representative_capture()
        conclusions = build_conclusions(frames, roles, index)
        assert find_ungrounded_conclusions({"conclusions": conclusions}) == []

    def test_no_punt_language_in_any_conclusion(self):
        """removed punt: 어떤 결론 메시지에도 '추가 조사 필요' 류 표현이 없어야 한다."""
        frames, roles, index = representative_capture()
        conclusions = build_conclusions(frames, roles, index)
        offenders = [c.message for c in conclusions if contains_punt_language(c.message)]
        assert offenders == [], f"punt 표현이 남아있음: {offenders}"

    def test_rendered_analyze_output_has_no_punt_lines(self):
        """렌더링된 analyze() 라인에도 punt 표현이 없어야 한다."""
        frames, roles, index = representative_capture()
        section = analyze(frames, roles, index)
        punt_lines = [ln for ln in section.lines if contains_punt_language(ln)]
        assert punt_lines == [], f"punt 라인이 남아있음: {punt_lines}"

    def test_every_diagnosis_path_is_exercised(self):
        """대표 캡처가 실제로 모든 진단 코드 경로를 자극하는지 확인 (회귀 방지)."""
        frames, roles, index = representative_capture()
        messages = [c.message for c in build_conclusions(frames, roles, index)]
        joined = " | ".join(messages)
        for needle in (
            "Ping Loss",          # ping loss WARNING
            "높은 Retry Rate",     # high retry WARNING
            "Retry Rate:",        # mid retry INFO
            "RSSI 최저값",         # low rssi WARNING
            "Retry 폭증",          # retry burst WARNING
            "잦은 로밍",           # frequent roaming INFO
            "정상",               # normal INFO
            "TX power",           # suggestion path1
            "히스테리시스",        # suggestion path2
            "직접 점검 권장",      # suggestion path3 (replaced punt)
        ):
            assert needle in joined, f"진단 경로 미자극: {needle!r}"
