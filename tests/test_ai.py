"""AI 모듈 테스트 — 프롬프트 생성, 프로바이더 분기."""
from ai.prompts import build_review_prompt
from ai.reviewer import SYSTEM_PROMPT


class TestBuildReviewPrompt:
    def test_basic_structure(self):
        structured = {
            "overview": {"total_frames": 1000, "duration_sec": 60, "retry_pct": 5,
                         "devices": [{"mac": "aa:bb", "role": "STA", "name": "STA1", "count": 500}]},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        prompt = build_review_prompt(structured)
        assert "분석 개요" in prompt
        assert "1,000" in prompt or "1000" in prompt
        assert "조치 방안" in prompt

    def test_with_ping_data(self):
        structured = {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0, "devices": []},
            "ping": {
                "pairs": [{"rtt_ms": 5.0}, {"rtt_ms": 10.0}],
                "losses": [{"epoch": 1000}],
            },
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        prompt = build_review_prompt(structured)
        assert "Ping" in prompt
        assert "loss" in prompt.lower() or "미응답" in prompt

    def test_with_roaming(self):
        structured = {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0, "devices": []},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": [
                {"is_slow": True, "gap_ms": 200},
                {"is_slow": False, "gap_ms": 50},
            ]},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        prompt = build_review_prompt(structured)
        assert "로밍" in prompt

    def test_with_signal(self):
        structured = {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0, "devices": []},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": []},
            "signal": {"stas": {"STA1": {"rssi_avg": -65, "frame_count": 50}}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        prompt = build_review_prompt(structured)
        assert "신호" in prompt
        assert "STA1" in prompt

    def test_with_delays(self):
        structured = {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0, "devices": []},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": [
                {"duration_sec": 2.5, "cause": "roaming", "affected_pings": 3},
            ]},
            "anomaly_frames": {"anomalies": []},
        }
        prompt = build_review_prompt(structured)
        assert "지연" in prompt

    def test_with_anomalies(self):
        structured = {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0, "devices": []},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": [
                {"severity": "high", "type": "deauth", "description": "DeAuth 15건"},
            ]},
        }
        prompt = build_review_prompt(structured)
        assert "이상" in prompt


class TestSystemPrompt:
    def test_system_prompt_content(self):
        assert "WiFi" in SYSTEM_PROMPT or "802.11" in SYSTEM_PROMPT
        assert "한국어" in SYSTEM_PROMPT
