"""진단 임계값 단일 소스(analyzer/core/thresholds.py) 테스트.

canonical 기준(자동차 운용, SYSTEM_PROMPT와 동일)이 상수·심각도 헬퍼·
각 소비자(SYSTEM_PROMPT, 로밍 slow 판정)에 일관되게 반영되는지 검증한다.
"""
from analyzer.core import thresholds as th
from analyzer.core.modules.roaming import SLOW_THRESHOLD_MS
from ai.reviewer import SYSTEM_PROMPT


class TestCanonicalValues:
    def test_constants_match_automotive_baseline(self):
        assert (th.RETRY_WARN_PCT, th.RETRY_DANGER_PCT) == (5, 15)
        assert (th.ROAM_GAP_WARN_MS, th.ROAM_GAP_DANGER_MS) == (50, 100)
        assert th.ROAM_PCAP_TOTAL_SLOW_MS == 100
        assert th.STA_ROAM_SLOW_MS == 150
        assert (th.RTT_WARN_MS, th.RTT_DANGER_MS) == (30, 80)
        assert (th.LOSS_WARN_PCT, th.LOSS_DANGER_PCT) == (1, 5)
        assert (th.RSSI_WARN_DBM, th.RSSI_DANGER_DBM) == (-65, -75)
        assert (th.MCS_WARN, th.MCS_DANGER) == (6, 3)

    def test_slow_roaming_threshold_synced(self):
        """roaming.py의 느린 로밍 경계는 canonical 위험 경계와 동일해야 한다."""
        assert SLOW_THRESHOLD_MS == th.ROAM_GAP_DANGER_MS


class TestSeverityHelpers:
    def test_retry_severity(self):
        assert th.retry_severity(5) == "good"       # 경계값은 낮은 단계
        assert th.retry_severity(5.1) == "warn"
        assert th.retry_severity(15) == "warn"
        assert th.retry_severity(18.3) == "danger"  # 감사 사례 — 이제 '위험'

    def test_roam_gap_severity(self):
        assert th.roam_gap_severity(50) == "good"
        assert th.roam_gap_severity(80) == "warn"
        assert th.roam_gap_severity(101) == "danger"

    def test_rtt_severity(self):
        assert th.rtt_severity(30) == "good"
        assert th.rtt_severity(50) == "warn"
        assert th.rtt_severity(81) == "danger"

    def test_loss_severity(self):
        assert th.loss_severity(1) == "good"
        assert th.loss_severity(3) == "warn"
        assert th.loss_severity(5.5) == "danger"

    def test_rssi_severity(self):
        assert th.rssi_severity(-65) == "good"
        assert th.rssi_severity(-70) == "warn"
        assert th.rssi_severity(-76) == "danger"

    def test_mcs_severity(self):
        assert th.mcs_severity(6) == "good"
        assert th.mcs_severity(4) == "warn"
        assert th.mcs_severity(2) == "danger"


class TestSystemPromptInjection:
    def test_system_prompt_uses_canonical_numbers(self):
        """SYSTEM_PROMPT의 임계값 문구는 상수에서 주입된다 (문구 유지)."""
        assert f"≤{th.RETRY_WARN_PCT}% 양호" in SYSTEM_PROMPT
        assert f">{th.RETRY_DANGER_PCT}% 위험" in SYSTEM_PROMPT
        assert f">{th.STA_ROAM_SLOW_MS}ms" in SYSTEM_PROMPT
        assert f">{th.ROAM_PCAP_TOTAL_SLOW_MS}ms" in SYSTEM_PROMPT
        assert f"≤{th.RTT_WARN_MS}ms 양호" in SYSTEM_PROMPT
        assert f">{th.LOSS_DANGER_PCT}% 위험" in SYSTEM_PROMPT
        assert f"≥{th.RSSI_WARN_DBM}dBm 양호" in SYSTEM_PROMPT
        assert f"<{th.RSSI_DANGER_DBM} 위험" in SYSTEM_PROMPT
        assert f"HE {th.MCS_WARN} 이상 양호" in SYSTEM_PROMPT
