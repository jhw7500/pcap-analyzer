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

    def test_system_prompt_has_correlation_format_guidance(self):
        """SYSTEM_PROMPT는 종합 결론(correlation) 응답 형식을 정의해야 한다."""
        assert "C{n}" in SYSTEM_PROMPT
        assert "가능한 가설" in SYSTEM_PROMPT
        assert "대안 해석" in SYSTEM_PROMPT
        assert "추가 검증" in SYSTEM_PROMPT

    def test_system_prompt_warns_against_chipset_assumption(self):
        """88Q9098도 사용자 설정으로 동작이 바뀌므로 단일 칩셋 가정을 피하라는 가이드 필수."""
        assert "사용자 설정" in SYSTEM_PROMPT or "사용자 측 설정" in SYSTEM_PROMPT


class TestCorrelationsInPrompt:
    """진단 결과의 correlations 필드가 prompt에 명시적으로 포함되는지 검증.

    PR #5에서 추가된 다중 신호 결합 결론을 AI가 활용하도록 _build_diagnosis_section
    이 correlations 섹션을 노출한다.
    """
    def _structured(self, correlations):
        return {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 5,
                         "devices": []},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
            "diagnosis": {"correlations": correlations} if correlations is not None else {},
        }

    def test_correlations_section_included_when_present(self):
        correlations = [{
            "title": "약전계로 인한 multi-symptom (느린 로밍 동반)",
            "confidence": 0.87,
            "sta_name": "STA1", "sta_mac": "AA:BB:CC:DD:EE:01",
            "time_window": {"start_epoch": 1000.0, "end_epoch": 1010.0},
            "frame_refs": [1, 2, 3, 4, 5],
            "signals": [
                {"type": "weak_rssi"}, {"type": "high_retry"},
                {"type": "slow_roaming"},
            ],
            "explanation": "RSSI -65dBm · Retry 27% · 느린 로밍 3회",
        }]
        prompt = build_review_prompt(self._structured(correlations))
        assert "종합 결론" in prompt
        assert "C1:" in prompt
        assert "약전계로 인한 multi-symptom" in prompt
        assert "0.87" in prompt
        assert "STA1" in prompt
        assert "weak_rssi" in prompt
        assert "high_retry" in prompt
        assert "duration=10.0s" in prompt
        assert "5건" in prompt  # frame_refs 개수
        assert "RSSI -65dBm" in prompt  # explanation

    def test_correlations_section_omitted_when_empty(self):
        """correlations가 빈 리스트면 종합 결론 섹션 자체가 prompt에 없어야."""
        prompt = build_review_prompt(self._structured([]))
        assert "종합 결론(다중 신호 결합" not in prompt

    def test_correlations_section_omitted_when_missing(self):
        """correlations 키 자체가 없어도 (구버전 데이터) 에러 없이 처리."""
        structured = self._structured(None)
        prompt = build_review_prompt(structured)
        assert "종합 결론(다중 신호 결합" not in prompt

    def test_input_order_is_preserved(self):
        """correlations 입력 순서가 prompt에서 보존된다(caller가 confidence 정렬 후 전달).

        build_review_prompt 자체는 재정렬하지 않으며 build_correlations(causality.py)
        가 confidence 내림차순으로 정렬해 넘기는 것을 신뢰한다.
        """
        correlations = [
            {"title": "혼잡으로 인한 로밍 영향", "confidence": 0.9,
             "sta_name": "STA1", "sta_mac": "AA",
             "time_window": {"start_epoch": 100, "end_epoch": 110},
             "frame_refs": [1], "signals": [{"type": "high_retry"}],
             "explanation": "ex1"},
            {"title": "약전계로 인한 retry 폭증", "confidence": 0.65,
             "sta_name": "STA2", "sta_mac": "BB",
             "time_window": {"start_epoch": 200, "end_epoch": 210},
             "frame_refs": [2], "signals": [{"type": "weak_rssi"}],
             "explanation": "ex2"},
        ]
        prompt = build_review_prompt(self._structured(correlations))
        assert "C1:" in prompt and "C2:" in prompt
        assert prompt.index("C1:") < prompt.index("C2:")

    def test_review_request_item_zero_only_when_correlations_present(self):
        """항목 0(correlation별 가설)은 correlations가 있을 때만 prompt에 emit."""
        # correlations 있는 케이스
        present_prompt = build_review_prompt(self._structured([{
            "title": "x", "confidence": 0.7, "sta_name": "STA",
            "time_window": {"start_epoch": 0, "end_epoch": 1},
            "frame_refs": [1], "signals": [{"type": "high_retry"}],
            "explanation": "x"}]))
        assert "0. **종합 결론(correlation)별 가설**" in present_prompt
        # correlations 없는 케이스 — 항목 0 자체가 없어야
        empty_prompt = build_review_prompt(self._structured([]))
        assert "종합 결론(correlation)별 가설" not in empty_prompt
        # 그래도 1~5 항목은 그대로
        assert "1. **가장 심각한 문제" in empty_prompt

    def test_correlations_cap_at_five(self):
        """correlations가 5개를 넘으면 상위 5건만 prompt에 들어간다."""
        many = [{
            "title": f"Title{i}", "confidence": 0.5,
            "sta_name": f"STA{i}", "sta_mac": f"AA:{i:02d}",
            "time_window": {"start_epoch": i*10, "end_epoch": i*10+5},
            "frame_refs": [i], "signals": [{"type": "high_retry"}],
            "explanation": f"ex{i}",
        } for i in range(1, 7)]  # 6개
        prompt = build_review_prompt(self._structured(many))
        assert "C5:" in prompt
        assert "C6:" not in prompt
        assert "Title6" not in prompt

    def test_non_dict_correlation_items_skipped(self):
        """list 안에 dict 아닌 항목(stale 문자열 등)이 섞여도 dict만 렌더링."""
        mixed = [
            {"title": "Valid1", "confidence": 0.8, "sta_name": "STA1",
             "time_window": {"start_epoch": 0, "end_epoch": 5},
             "frame_refs": [1], "signals": [{"type": "high_retry"}],
             "explanation": "ok"},
            "stale-string-not-a-dict",
            {"title": "Valid2", "confidence": 0.7, "sta_name": "STA2",
             "time_window": {"start_epoch": 10, "end_epoch": 15},
             "frame_refs": [2], "signals": [{"type": "weak_rssi"}],
             "explanation": "ok"},
        ]
        prompt = build_review_prompt(self._structured(mixed))
        assert "Valid1" in prompt and "Valid2" in prompt
        assert "stale-string-not-a-dict" not in prompt

    def test_correlation_with_non_numeric_confidence_does_not_crash(self):
        """confidence가 문자열/None이어도 prompt 생성이 ValueError 없이 진행된다."""
        bad = [{
            "title": "BadConf", "confidence": "not-a-number",
            "sta_name": "STA", "time_window": {"start_epoch": 0, "end_epoch": 5},
            "frame_refs": [1], "signals": [{"type": "high_retry"}],
            "explanation": "x",
        }]
        prompt = build_review_prompt(self._structured(bad))
        assert "BadConf" in prompt
        # confidence는 0.00으로 fallback
        assert "conf=0.00" in prompt

    def test_correlation_with_non_dict_time_window_does_not_crash(self):
        """time_window가 dict 아닌 경우(예: 잘못된 캐시) AttributeError 없이 진행."""
        bad = [{
            "title": "BadTW", "confidence": 0.5, "sta_name": "STA",
            "time_window": "not-a-dict",
            "frame_refs": [1], "signals": [{"type": "high_retry"}],
            "explanation": "x",
        }]
        prompt = build_review_prompt(self._structured(bad))
        assert "BadTW" in prompt
        # duration은 빠진 채로 헤더 라인이 만들어진다
        assert "duration=" not in prompt
