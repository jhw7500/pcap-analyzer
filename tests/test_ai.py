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

    def test_system_prompt_conf_format_matches_user_prompt(self):
        """SYSTEM의 conf 표기는 user prompt 헤더(`conf=...`)와 일치한다.

        formatting 불일치(conf= vs conf )는 LLM이 답변 헤더를 user 측 형식과
        다르게 만들 가능성을 키운다.
        """
        assert "conf={confidence}" in SYSTEM_PROMPT

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

    def test_cap_applied_after_non_dict_filter(self):
        """`[:5]` cap은 non-dict 필터 후 적용 — stale 항목 때문에 valid 5건이
        4건으로 줄어드는 silent loss 방지. 정확히 5개 valid가 렌더돼야."""
        mixed = [
            "stale1",
            "stale2",
            *[
                {"title": f"V{i}", "confidence": 0.5, "sta_name": "STA",
                 "time_window": {"start_epoch": i*10, "end_epoch": i*10+5},
                 "frame_refs": [i], "signals": [{"type": "high_retry"}],
                 "explanation": "x"}
                for i in range(1, 8)  # 7 dict, total 9 items
            ],
        ]
        prompt = build_review_prompt(self._structured(mixed))
        # raw cap 정책이면 V1-V3만 렌더, filter-first면 V1-V5
        assert "V1" in prompt and "V5" in prompt
        assert "V6" not in prompt  # cap에 의해 자름
        assert "V3" in prompt  # 이전 버그였다면 V3까지만 → 검증

    def test_c_numbering_has_no_gap_when_non_dict_items_present(self):
        """non-dict 항목이 list 첫 위치에 있어도 C-numbering은 C1부터 시작.

        enumerate 위치 인덱스로 매기던 이전 버전은 [str, dict]에서 C2부터 시작해
        SYSTEM의 ### C{n} 답변 형식과 짝짓기 어려웠다. rendered counter로 갭 없음.
        """
        mixed = [
            "stale-leading",
            {"title": "FirstValid", "confidence": 0.8, "sta_name": "STA",
             "time_window": {"start_epoch": 0, "end_epoch": 5},
             "frame_refs": [1], "signals": [{"type": "high_retry"}],
             "explanation": "x"},
            {"title": "SecondValid", "confidence": 0.7, "sta_name": "STA",
             "time_window": {"start_epoch": 10, "end_epoch": 15},
             "frame_refs": [2], "signals": [{"type": "weak_rssi"}],
             "explanation": "y"},
        ]
        prompt = build_review_prompt(self._structured(mixed))
        assert "C1: FirstValid" in prompt
        assert "C2: SecondValid" in prompt
        assert "C3:" not in prompt

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

    def test_build_review_prompt_handles_none_diagnosis(self):
        """structured = {'diagnosis': None}에서도 AttributeError 없이 진행.

        dict.get(k, default)는 키가 있고 value가 None이면 default를 무시하고
        None을 반환하므로 `or {}` 폴백이 필요. 이 보호가 없으면 line 332에서
        diagnosis.get('correlations') 호출이 AttributeError 발생.
        """
        structured = {
            "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0,
                         "devices": []},
            "ping": {"pairs": [], "losses": []},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
            "diagnosis": None,  # ← 외부 캐시/직렬화 라운드트립 후 발생 가능
        }
        prompt = build_review_prompt(structured)  # AttributeError 없이 완료해야
        assert "분석 개요" in prompt
        # 종합 결론 섹션과 item 0은 None diagnosis라 emit 안 됨
        assert "종합 결론(다중 신호 결합" not in prompt
        assert "종합 결론(correlation)별 가설" not in prompt

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


def _base_structured(**extra):
    """build_review_prompt가 요구하는 최소 구조 + extra 키 병합."""
    base = {
        "overview": {"total_frames": 100, "duration_sec": 10, "retry_pct": 0, "devices": []},
        "ping": {"pairs": [], "losses": []},
        "roaming": {"sequences": []},
        "signal": {"stas": {}},
        "delay_zones": {"delay_zones": []},
        "anomaly_frames": {"anomalies": []},
    }
    base.update(extra)
    return base


class TestSignalCliffsInPrompt:
    """signal_cliffs는 {STA명: {cliffs:[...]}} 구조 — 평탄화 렌더 회귀 가드."""

    def test_sta_keyed_cliffs_rendered(self):
        s = _base_structured(signal_cliffs={
            "STA1": {"cliffs": [
                {"epoch": 1001.5, "rssi_before": -50, "rssi_after": -70,
                 "drop_db": 20, "duration_sec": 0.5},
            ]},
        })
        prompt = build_review_prompt(s)
        assert "신호 절벽" in prompt
        assert "STA1" in prompt
        assert "20" in prompt  # drop_db — 과거엔 shape 불일치로 0건이라 누락

    def test_empty_cliffs_no_section(self):
        s = _base_structured(signal_cliffs={"STA1": {"cliffs": []}})
        assert "신호 절벽" not in build_review_prompt(s)

    def test_non_dict_cliff_entries_skipped(self):
        s = _base_structured(signal_cliffs={
            "STA1": {"cliffs": ["stale", {"epoch": 1, "drop_db": 12}]},
        })
        prompt = build_review_prompt(s)
        assert "신호 절벽(RSSI 급강하) 1건" in prompt  # dict 1건만 집계


class TestStaDiagsInPrompt:
    """sta_diags는 list + nested metrics — report.py와 동일 계약 회귀 가드."""

    def test_list_shape_rendered_with_nested_metrics(self):
        s = _base_structured(diagnosis={"sta_diags": [
            {"name": "STA1", "mac": "aa:bb", "score": 72,
             "scores": {"retry": 60, "rssi": 80, "roaming": 75},
             "metrics": {"retry_pct": 27.3, "rssi_avg": -68, "roaming_count": 4},
             "issues": []},
        ]})
        prompt = build_review_prompt(s)
        assert "STA별 사전 진단" in prompt
        assert "STA1" in prompt
        assert "27.3" in prompt   # nested metric — dict로 소비하던 과거엔 누락
        assert "score=72" in prompt

    def test_non_dict_element_skipped(self):
        s = _base_structured(diagnosis={"sta_diags": [
            "stale", {"name": "STA2", "metrics": {"retry_pct": 10}},
        ]})
        prompt = build_review_prompt(s)
        assert "STA2" in prompt and "10" in prompt

    def test_empty_list_no_section(self):
        s = _base_structured(diagnosis={"sta_diags": []})
        assert "STA별 사전 진단" not in build_review_prompt(s)


class TestOverviewTypeDistInPrompt:
    """overview.type_dist가 프롬프트의 '프레임 타입 분포'로 렌더되는지(#7)."""

    def test_type_dist_rendered(self):
        ov = {"total_frames": 100, "duration_sec": 10, "retry_pct": 0,
              "devices": [], "type_dist": {"Management": 60, "Data": 40}}
        prompt = build_review_prompt(_base_structured(overview=ov))
        assert "프레임 타입 분포" in prompt
        assert "Management" in prompt


class TestRetryPeakMcsInPrompt:
    """per_bucket의 retry 피크에 avg_mcs/mcs_breakdown이 렌더되는지(#11)."""

    def test_avg_mcs_rendered_in_peak(self):
        s = _base_structured(device_stats={
            "STA1": {
                "role": "STA", "total_frames": 200, "tx_frames": 200,
                "retry_count": 60, "retry_pct": 30,
                "per_bucket": [
                    {"total": 100, "retry": 40, "retry_pct": 40.0,
                     "avg_mcs": 7.5, "mcs_breakdown": "HE MCS7×80"},
                ],
            },
        })
        prompt = build_review_prompt(s)
        assert "Retry 피크" in prompt
        assert "7.5" in prompt        # avg_mcs — 과거엔 orphan key라 'MCS -'
        assert "MCS -)" not in prompt


class TestDiagnosisSectionInPrompt:
    """_build_diagnosis_section: 실제 _structured_diagnosis 형태(dict health/summary).
    dead elif(비-dict stringify) 제거 후, 비-dict는 누락되는지(report.py와 동일 정책)."""

    def test_full_diagnosis_rendered(self):
        s = _base_structured(diagnosis={
            "health": {"score": 75, "grade": "주의", "color": "yellow"},
            "component_scores": {"retry": 60, "loss": 80, "roaming": 70},
            "summary": {"total_frames": 1000, "retry_pct": 12, "loss_pct": 3,
                        "roaming_total": 5, "roaming_slow": 2,
                        "delay_zones": 1, "anomaly_count": 0},
            "issues": [{"severity": "high", "category": "Retry",
                        "msg": "retry 폭증", "action": "확인"}],
            "sta_diags": [],
        })
        prompt = build_review_prompt(s)
        assert "사전 계산된 진단" in prompt
        assert "score=75" in prompt
        assert "retry_pct=12" in prompt        # summary dict 분기
        assert "컴포넌트 점수" in prompt

    def test_non_dict_health_summary_dropped(self):
        s = _base_structured(diagnosis={
            "health": "BADHEALTH", "summary": "BADSUMMARY",
            "issues": [], "sta_diags": [],
        })
        prompt = build_review_prompt(s)
        # dead elif 제거 — 비-dict는 stringify되지 않고 그냥 누락
        assert "BADHEALTH" not in prompt
        assert "BADSUMMARY" not in prompt
