"""STA 로그 → 종합 진단 연결 (관측 커버리지 보고).

pcap은 **전파에 나온 프레임만** 본다 — 실측 776건 대조로 로밍 전체 97.0ms 중
pcap이 보는 건 25.1ms뿐이고 74.1%가 전파 밖(스캔·로밍 판단·드라이버 처리·키
설치)이다. 그 사실이 지금까지 프론트 카드 한 곳에만 있었고 리포트·AI 프롬프트·
이슈는 전혀 몰랐다.

이 PR은 **판정을 건드리지 않는다**. `is_slow`·건강도·`measurable` 분모는 한 줄도
바뀌지 않는다 — STA 체감 기준 임계값의 운용 근거가 아직 없기 때문이다
(`thresholds.py`는 모든 임계에 근거를 요구한다). 이 PR이 내는 실측 분포가 그
근거가 되고, 판정 승격은 후속 PR로 간다.

따라서 이 파일의 가장 중요한 단언은 **"STA 로그가 없으면 아무것도 안 변한다"**와
**"있어도 판정 축은 안 변한다"** 두 가지다.
"""

import json

import pytest

from analyzer.web.structured import (
    ROAM_COVERAGE_LOW_PCT,
    ROAM_COVERAGE_MIN_PAIRS,
    _roam_coverage,
    _structured_diagnosis,
)

STA1 = "00:11:22:33:44:01"
AP1 = "aa:bb:cc:dd:ee:01"


def _seq(total_roam_ms=25.0, sta_total_ms=97.0, *, fnum=100, sta=STA1, **extra):
    """로밍 시퀀스 1건. `sta_total_ms=None`이면 sta_log를 아예 붙이지 않는다.

    부착 실패는 "sta_log 키 부재"로 표현된다(`station_match.py:329`는 성공 시에만
    주입한다) — 빈 dict가 아니다. 그 구분이 분모 오염을 막는 지점이라 픽스처도
    같은 형태여야 한다.
    """
    s = {
        "sta": sta, "sta_name": "STA1", "ap": AP1, "ap_name": "AP1",
        "gap_ms": 5.0, "is_slow": False, "slow_basis": "total",
        "auth_epoch": 1000.0, "assoc_epoch": 1000.02,
        "auth_fnum": fnum, "assoc_fnum": fnum + 1,
        "assoc_type": "ReassocReq",
        "total_roam_ms": total_roam_ms,
    }
    if sta_total_ms is not None:
        s["sta_log"] = {
            "total_ms": sta_total_ms, "assoc_ms": 20.0, "residual_ms": 12.0,
            "source": "1호기", "scan_ms": 61.7, "reason": "RSSI diff: 17dB",
        }
    s.update(extra)
    return s


def _structured(seqs, *, station_logs=None, stas=None, device_stats=None):
    st = {
        "overview": {"total_frames": 1000, "retry_pct": 0, "devices": []},
        "ping": {"full_list": [], "stats": {}},
        "roaming": {"sequences": seqs, "roaming_frame_count": len(seqs)},
        "signal": {"stas": stas or {}, "aps": {}},
        "device_stats": device_stats or {},
        "delay_zones": {"delay_zones": []},
        "anomaly_frames": {},
        "signal_cliffs": {},
    }
    if station_logs is not None:
        st["station_logs"] = station_logs
    return st


def _diag(seqs, **kw):
    return _structured_diagnosis(_structured(seqs, **kw), [], None)


class TestRoamCoverage:
    """순수 함수 — 대조 가능한 시퀀스만 분모로 쓰고, 없으면 값을 지어내지 않는다."""

    def test_pairs_only_sequences_with_both_values(self):
        """sta_log만 있거나 total_roam_ms만 있는 건 대조 불가라 분모에서 빠진다."""
        seqs = [
            _seq(25.0, 97.0),
            _seq(25.0, None),                 # sta_log 미부착
            _seq(None, 97.0),                 # 4-way 미포착 → pcap 전체 모름
            _seq(27.0, 99.0),
        ]
        matched, sta_p50, pcap_p50, visible = _roam_coverage(seqs)
        assert matched == 2
        assert sta_p50 == 98.0                # (97+99)/2 — 표준 중앙값
        assert pcap_p50 == 26.0               # (25+27)/2
        assert visible == pytest.approx(26.5, abs=0.05)

    def test_no_pairs_returns_none_not_zero(self):
        """대조 0건이면 비율은 0%가 아니라 None이다 — 0%는 '전부 못 봤다'는 주장이다."""
        assert _roam_coverage([_seq(25.0, None)]) == (0, None, None, None)
        assert _roam_coverage([]) == (0, None, None, None)

    def test_zero_sta_total_is_unmeasurable_not_infinite(self):
        """체감 0ms면 비율이 무한대가 된다 — 값을 지어내지 않고 None."""
        matched, sta_p50, pcap_p50, visible = _roam_coverage([_seq(25.0, 0.0)])
        assert matched == 1
        assert sta_p50 == 0.0
        assert visible is None

    def test_bool_is_not_a_measurement(self):
        """bool은 int의 서브클래스라 True가 1ms로 통과한다 — 명시적으로 배제."""
        matched, _, _, _ = _roam_coverage([_seq(True, True), _seq(25.0, 97.0)])
        assert matched == 1

    def test_matches_frontend_definition(self):
        """화면(charts.js)과 같은 정의 — 두 p50을 각각 구한 뒤 비율.

        시퀀스별 비율의 p50이 아니다. 둘은 다른 값이며, 백엔드와 화면이 다른
        수치를 말하면 사용자는 어느 쪽을 믿을지 알 수 없다.
        """
        # 시퀀스별 비율이면 (10/100, 90/100)의 p50 = 50%.
        # p50끼리의 비율이면 50/100 = 50%... 가 아니라 값이 갈리도록 비대칭 구성.
        seqs = [_seq(10.0, 100.0), _seq(90.0, 100.0), _seq(20.0, 40.0)]
        matched, sta_p50, pcap_p50, visible = _roam_coverage(seqs)
        assert matched == 3
        assert sta_p50 == 100.0               # median(100, 100, 40)
        assert pcap_p50 == 20.0               # median(10, 90, 20)
        assert visible == pytest.approx(20.0, abs=0.05)
        # 시퀀스별 비율의 median이었다면 50.0이 나왔을 것이다.
        assert visible != pytest.approx(50.0, abs=0.05)


class TestCoverageIssueEvidence:
    """이슈는 근거를 대야 하고, 인과 추론을 오염시키면 안 된다."""

    def test_low_coverage_emits_issue_with_wireless_frame_refs(self):
        seqs = [_seq(25.0, 97.0, fnum=100 + i * 10) for i in range(5)]
        d = _diag(seqs)
        issues = [i for i in d["issues"] if i.get("category") == "관측"]
        assert len(issues) == 1
        issue = issues[0]
        # 근거는 무선 프레임(auth_fnum/assoc_fnum)에서 소싱 — 유선 frame.number를
        # 섞으면 프레임 테이블 조회가 깨진다.
        assert issue["frame_refs"]
        assert set(issue["frame_refs"]) <= {100 + i * 10 for i in range(5)} | {
            101 + i * 10 for i in range(5)
        }
        assert issue["time_window"]["start_epoch"] == 1000.0

    def test_issue_carries_no_signal_type(self):
        """causality가 distinct signal_type 수로 confidence를 정한다.

        관측 커버리지는 특정 시각의 사건이 아니라 캡처 전체의 성질이라 어떤
        클러스터와도 시간이 겹친다. signal_type을 주면 인과 confidence를 부풀린다.
        """
        d = _diag([_seq(25.0, 97.0, fnum=100 + i * 10) for i in range(5)])
        issue = [i for i in d["issues"] if i.get("category") == "관측"][0]
        assert "signal_type" not in issue

    def test_coverage_issue_is_not_collected_as_causality_signal(self):
        """실제 causality 수집기를 통과시켜 확인 — signal_type 부재가 곧 제외다.

        `_collect_signals`는 `if not stype ... continue`로 signal_type 없는 이슈를
        건너뛴다(`causality.py:180-183`). 관측 커버리지에 signal_type을 주지 않은
        결정이 이 계약에 기대고 있으므로, 계약이 바뀌면 커버리지가 인과 confidence를
        부풀리기 시작한다 — 그 순간을 여기서 잡는다.

        실측(143만 프레임): 관측 이슈가 medium 그룹에 끼면서 delay_zone의
        net issue_index가 9→10으로 밀렸지만, 역참조한 대상 이슈는 전부 동일했고
        correlation 5건의 구성·confidence도 그대로였다.
        """
        from analyzer.core.modules.causality import _collect_signals

        d = _diag([_seq(25.0, 97.0, fnum=100 + i * 10) for i in range(5)])
        issues = d["issues"]
        assert any(i.get("category") == "관측" for i in issues), "이슈 자체는 있어야 한다"
        _, net_signals = _collect_signals(d)
        assert all(
            issues[s["issue_index"]].get("category") != "관측" for s in net_signals
        ), "관측 커버리지가 인과 신호로 수집되면 안 된다"

    def test_good_coverage_emits_nothing(self):
        """pcap이 대부분을 보고 있으면 경고할 이유가 없다."""
        seqs = [_seq(90.0, 97.0, fnum=100 + i * 10) for i in range(5)]
        d = _diag(seqs)
        assert [i for i in d["issues"] if i.get("category") == "관측"] == []
        assert d["summary"]["roaming_pcap_visible_pct"] == pytest.approx(92.8, abs=0.1)

    def test_too_few_pairs_makes_no_claim(self):
        """표본 2건으로 '커버리지 26%'라고 단정하지 않는다."""
        seqs = [_seq(25.0, 97.0, fnum=100 + i * 10)
                for i in range(ROAM_COVERAGE_MIN_PAIRS - 1)]
        d = _diag(seqs)
        assert [i for i in d["issues"] if i.get("category") == "관측"] == []
        # 값 자체는 숨기지 않는다 — 이슈로 단정하지 않을 뿐.
        assert d["summary"]["roaming_sta_log_matched"] == ROAM_COVERAGE_MIN_PAIRS - 1

    def test_threshold_boundary_is_not_low(self):
        """경계값 자체는 낮은 단계에 포함(thresholds.py 규약)."""
        seqs = [_seq(50.0, 100.0, fnum=100 + i * 10) for i in range(5)]
        d = _diag(seqs)
        assert d["summary"]["roaming_pcap_visible_pct"] == ROAM_COVERAGE_LOW_PCT
        assert [i for i in d["issues"] if i.get("category") == "관측"] == []


class TestJudgmentAxisUnchanged:
    """이 PR의 핵심 안전 단언 — 판정은 한 톨도 안 변한다."""

    def test_health_and_scores_identical_with_and_without_sta_log(self):
        """같은 로밍에 STA 로그만 붙였다 뗐다 해도 점수·판정은 동일해야 한다."""
        with_log = _diag([_seq(25.0, 97.0, fnum=100 + i * 10) for i in range(5)])
        without = _diag([_seq(25.0, None, fnum=100 + i * 10) for i in range(5)])
        assert with_log["health"] == without["health"]
        assert with_log["component_scores"] == without["component_scores"]
        for key in ("roaming_total", "roaming_slow", "roaming_measurable",
                    "roaming_unmeasured", "loss_pct_used", "loss_basis"):
            assert with_log["summary"][key] == without["summary"][key], key

    def test_no_station_log_leaves_diagnosis_byte_identical(self):
        """station_logs 키가 아예 없는 구버전 입력에서 새 키가 값을 지어내지 않는다.

        새 summary 키는 존재하되 전부 0/None이어야 한다 — 그래야 리포트·AI가
        "커버리지 0%"(= 전부 못 봤다)로 오독하지 않는다.
        """
        d = _diag([_seq(25.0, None, fnum=100 + i * 10) for i in range(5)])
        assert d["summary"]["roaming_sta_log_matched"] == 0
        assert d["summary"]["roaming_sta_total_ms_p50"] is None
        assert d["summary"]["roaming_pcap_total_ms_p50"] is None
        assert d["summary"]["roaming_pcap_visible_pct"] is None
        assert [i for i in d["issues"] if i.get("category") == "관측"] == []

    def test_new_summary_keys_are_json_serializable(self):
        """None은 null로 나가야 한다 — NaN/Infinity는 JSON 파서를 깨뜨린다."""
        d = _diag([_seq(25.0, 0.0, fnum=100 + i * 10) for i in range(5)])
        dumped = json.dumps(d["summary"])
        assert "NaN" not in dumped and "Infinity" not in dumped

    def test_sta_diag_metrics_expose_matched_count(self):
        """STA별로도 대조 분모를 드러낸다 — 없으면 체감값이 전건 기준으로 읽힌다."""
        seqs = [_seq(25.0, 97.0, fnum=100 + i * 10) for i in range(3)]
        seqs += [_seq(25.0, None, fnum=200 + i * 10) for i in range(2)]
        d = _diag(
            seqs,
            stas={"STA1": {"mac": STA1, "rssi_avg": -60, "rssi_min": -70}},
            device_stats={"STA1": {"retry_pct": 1.0, "total_frames": 500}},
        )
        sta = [x for x in d["sta_diags"] if x["name"] == "STA1"][0]
        assert sta["metrics"]["sta_log_matched"] == 3
        assert sta["metrics"]["sta_log_total_ms_p50"] == 97.0
        # 판정 축은 그대로 — 5건 전부 measurable(slow_basis="total").
        assert sta["metrics"]["roaming_measurable"] == 5
        assert sta["metrics"]["slow_roaming"] == 0

    def test_sta_diag_metrics_none_when_no_log(self):
        d = _diag(
            [_seq(25.0, None, fnum=100 + i * 10) for i in range(3)],
            stas={"STA1": {"mac": STA1, "rssi_avg": -60, "rssi_min": -70}},
            device_stats={"STA1": {"retry_pct": 1.0, "total_frames": 500}},
        )
        sta = [x for x in d["sta_diags"] if x["name"] == "STA1"][0]
        assert sta["metrics"]["sta_log_matched"] == 0
        assert sta["metrics"]["sta_log_total_ms_p50"] is None


class TestReportRendering:
    """report.md — 구버전 결과의 출력이 한 글자도 변하면 안 된다."""

    def _report(self, seqs, station_logs=None):
        from analyzer.web.report import build_report_markdown

        st = _structured(seqs, station_logs=station_logs)
        st["diagnosis"] = _structured_diagnosis(st, [], None)
        return build_report_markdown({"structured": st})

    def test_roaming_table_keeps_eight_columns_without_sta_log(self):
        """sta_log가 없으면 기존 8열 그대로 — 구버전 report.md와 diff 0줄."""
        md = self._report([_seq(25.0, None)])
        header = [ln for ln in md.splitlines() if ln.startswith("| # | 시각(Auth)")][0]
        assert header.count("|") == 9          # 8열 → 파이프 9개
        assert "STA 체감" not in header

    def test_roaming_table_adds_column_with_sta_log(self):
        md = self._report([_seq(25.0, 97.0)])
        header = [ln for ln in md.splitlines() if ln.startswith("| # | 시각(Auth)")][0]
        assert "STA 체감(ms)" in header
        assert header.count("|") == 10         # 9열
        # 헤더·구분선·데이터 행의 열 수가 일치해야 GFM 표가 깨지지 않는다.
        idx = md.splitlines().index(header)
        rows = md.splitlines()[idx:idx + 3]
        assert len({r.count("|") for r in rows}) == 1

    def test_unmatched_row_says_unmatched_not_dash(self):
        """`-`만 두면 '지연 없음'으로 읽힌다 — 로그 미매칭임을 밝힌다."""
        md = self._report([_seq(25.0, 97.0), _seq(25.0, None)])
        assert "로그 미매칭" in md

    def test_station_log_section_present_and_absent(self):
        station_logs = {"stations": [{
            "name": "1호기", "sta_ip": "192.168.0.21", "sta_name": "STA2",
            "match_method": "ip", "attached": 281, "roam_total": 306,
            "total_ms_p50": 96.5, "scan_ms_p50": 61.7, "residual_mad_ms": 20.7,
            "warnings": ["오프셋 추정 잔차가 큽니다"],
        }]}
        md = self._report([_seq(25.0, 97.0)], station_logs=station_logs)
        assert "## STA 로그" in md
        assert "1호기" in md and "281/306" in md
        # warnings를 빠뜨리면 정렬 품질이 낮은 부착이 확정 수치로 읽힌다.
        assert "오프셋 추정 잔차가 큽니다" in md
        assert "## STA 로그" not in self._report([_seq(25.0, None)])


class TestReviewRound1Fixes:
    """PR #31 라운드 1 지적 반영분 — 전부 블로킹 미만이었으나 사실로 확인된 것들."""

    def _station(self, **kw):
        base = {
            "name": "1호기", "sta_ip": "192.168.0.21", "sta_name": "STA2",
            "match_method": "ip", "attached": 281, "roam_total": 306,
            "total_ms_p50": 96.5, "scan_ms_p50": 61.7, "residual_mad_ms": 20.7,
            "warnings": [],
        }
        base.update(kw)
        return base

    def test_failed_binding_claims_no_method(self):
        """[Codex P2] 매칭 실패에 방법 라벨을 붙이면 하지도 않은 근거를 주장한다.

        `bind_stations`는 실패 시 `match_method=""`를 준다(`station_match.py:163`).
        이걸 "시각 상관"으로 렌더하면 AI가 시각 상관으로 매칭됐다고 믿는다.
        """
        from ai.prompts import _build_station_log_section

        out = "\n".join(_build_station_log_section({"stations": [
            self._station(sta_name="", match_method="", total_ms_p50=None),
        ]}))
        assert "매칭 실패" in out
        assert "시각 상관" not in out

    def test_time_binding_is_labeled_time(self):
        """성공한 시각 상관 매칭은 그대로 "시각 상관"이어야 한다(과잉 수정 방지)."""
        from ai.prompts import _build_station_log_section

        out = "\n".join(_build_station_log_section({"stations": [
            self._station(match_method="time"),
        ]}))
        assert "시각 상관" in out and "매칭 실패" not in out

    def test_unknown_method_claims_nothing(self):
        """모르는 method 값은 방법을 주장하지 않는다 — 라벨 맵에 없으면 생략."""
        from ai.prompts import _build_station_log_section

        out = "\n".join(_build_station_log_section({"stations": [
            self._station(match_method="telepathy"),
        ]}))
        assert "STA2" in out
        assert "telepathy" not in out and "시각 상관" not in out

    def test_report_failed_binding_claims_no_method(self):
        """리포트도 같은 규약 — 라벨 맵 단일 소스."""
        from analyzer.web.report import _station_log_section

        out = "\n".join(_station_log_section(
            {"station_logs": {"stations": [
                self._station(sta_name="", match_method=""),
            ]}}, {},
        ))
        assert "매칭 실패" in out and "시각 상관" not in out

    def test_prompt_station_section_is_capped(self):
        """[Codex P2] 업로드는 호기 로그 60개까지 받는다 — 4000토큰 계약을 넘기면 안 된다."""
        from ai.prompts import PROMPT_MAX_STATIONS, _build_station_log_section

        many = [self._station(name=f"{i}호기") for i in range(PROMPT_MAX_STATIONS + 5)]
        out = "\n".join(_build_station_log_section({"stations": many}))
        assert out.count("호기 →") == PROMPT_MAX_STATIONS
        # 생략을 숨기면 LLM이 전건을 봤다고 오해한다.
        assert f"총 {len(many)}개 호기" in out

    def test_prompt_warnings_are_capped_and_disclosed(self):
        from ai.prompts import PROMPT_MAX_STATION_WARNINGS, _build_station_log_section

        n = PROMPT_MAX_STATION_WARNINGS + 4
        out = "\n".join(_build_station_log_section({"stations": [
            self._station(warnings=[f"경고{i}" for i in range(n)]),
        ]}))
        assert out.count("· 주의: ") == PROMPT_MAX_STATION_WARNINGS
        assert f"{n - PROMPT_MAX_STATION_WARNINGS}건 추가(생략)" in out

    def test_report_station_section_is_capped(self):
        from analyzer.web.report import REPORT_MAX_STATIONS, _station_log_section

        many = [self._station(name=f"{i}호기") for i in range(REPORT_MAX_STATIONS + 3)]
        out = "\n".join(_station_log_section(
            {"station_logs": {"stations": many}}, {}))
        assert out.count("| 192.168.0.21 |") == REPORT_MAX_STATIONS
        assert f"총 {len(many)}개 호기" in out

    def test_scan_note_only_when_scan_exists(self):
        """[Claude LOW] 스캔 값이 하나도 없으면 스캔 주의 문구도 나오지 않는다."""
        from ai.prompts import _build_station_log_section

        with_scan = "\n".join(_build_station_log_section({"stations": [self._station()]}))
        without = "\n".join(_build_station_log_section({"stations": [
            self._station(scan_ms_p50=None),
        ]}))
        assert "스캔은 ROAM 명령보다" in with_scan
        assert "스캔은 ROAM 명령보다" not in without

    def test_over_100_pct_is_flagged_not_capped(self):
        """[Gemini MEDIUM] 100% 초과는 정렬 이상 신호다 — 캡핑해 숨기면 안 된다.

        체감은 pcap 구간의 상위집합이라 정상이면 100%를 넘을 수 없다. 100으로
        잘라내면 "정상인데 딱 맞았다"로 읽혀 이상 신호가 사라진다.
        """
        from analyzer.web.report import _station_log_section

        diagnosis = {"summary": {
            "roaming_sta_log_matched": 10,
            "roaming_sta_total_ms_p50": 20.0,
            "roaming_pcap_total_ms_p50": 24.0,
            "roaming_pcap_visible_pct": 120.0,
        }}
        out = "\n".join(_station_log_section(
            {"station_logs": {"stations": [self._station()]}}, diagnosis))
        assert "120.0%" in out                      # 값을 숨기지 않는다
        assert "100%를 넘었다" in out
        assert "근거로 쓸 수 없다" in out
        assert "전파에 나타나지 않는다" not in out   # 정상 문구로 오독되면 안 된다

    def test_bool_is_not_a_measurement_in_display_paths(self):
        """[Claude MEDIUM] bool 가드를 집계 경로에만 두면 표시 경로가 True를 1ms로 찍는다."""
        from ai.prompts import _build_roaming_section
        from analyzer.web.report import _roaming_section

        seqs = [_seq(25.0, True), _seq(25.0, None)]
        md = "\n".join(_roaming_section({"roaming": {"sequences": seqs}}))
        header = [ln for ln in md.splitlines() if ln.startswith("| # | 시각(Auth)")][0]
        assert "STA 체감" not in header     # bool뿐이면 열 자체가 생기지 않는다
        prompt = "\n".join(_build_roaming_section({"sequences": seqs}))
        assert "sta_log.total_ms" not in prompt


class TestReviewRound2Fixes:
    """PR #31 라운드 2 지적(Codex P2×2) 반영분."""

    def _station(self, **kw):
        base = {
            "name": "1호기", "sta_ip": "192.168.0.21", "sta_name": "STA2",
            "match_method": "ip", "attached": 281, "roam_total": 306,
            "total_ms_p50": 96.5, "scan_ms_p50": 61.7, "residual_mad_ms": 20.7,
            "warnings": [],
        }
        base.update(kw)
        return base

    def _cov_summary(self, matched, visible=25.9):
        from analyzer.web.structured import coverage_is_reportable

        return {"summary": {
            "roaming_sta_log_matched": matched,
            "roaming_sta_total_ms_p50": 97.0,
            "roaming_pcap_total_ms_p50": 25.1,
            "roaming_pcap_visible_pct": visible,
            "roaming_coverage_reportable": coverage_is_reportable(matched, visible),
        }}

    def test_sample_threshold_is_one_rule_across_consumers(self):
        """[Codex P2] 진단·리포트·화면이 **같은 임계**를 써야 한다.

        진단은 `>= ROAM_COVERAGE_MIN_PAIRS`인데 리포트·화면이 `> 0`이면, 대조 1건에서
        진단은 "주장 안 함"인데 리포트만 "26%"라고 단정한다 — 같은 규칙을 세 곳에
        복제해 갈라진 이 저장소의 대표적 실패 모드다.
        """
        from analyzer.web.report import _station_log_section

        below = ROAM_COVERAGE_MIN_PAIRS - 1
        out_below = "\n".join(_station_log_section(
            {"station_logs": {"stations": [self._station()]}}, self._cov_summary(below)))
        # 표는 나오되 비율 단정 문장은 없어야 한다.
        assert "1호기" in out_below
        assert "%" not in out_below.split("| 로그 |")[0] or "전체의" not in out_below
        assert "전체의" not in out_below

        out_at = "\n".join(_station_log_section(
            {"station_logs": {"stations": [self._station()]}},
            self._cov_summary(ROAM_COVERAGE_MIN_PAIRS)))
        assert "전체의 **25.9%**" in out_at

    def test_reportable_flag_matches_diagnosis_decision(self):
        """화면이 읽는 플래그는 진단이 이슈를 낼 때 쓴 술어와 같은 값이어야 한다."""
        from analyzer.web.structured import coverage_is_reportable

        few = _diag([_seq(25.0, 97.0, fnum=100 + i * 10)
                     for i in range(ROAM_COVERAGE_MIN_PAIRS - 1)])
        enough = _diag([_seq(25.0, 97.0, fnum=100 + i * 10)
                        for i in range(ROAM_COVERAGE_MIN_PAIRS)])
        assert few["summary"]["roaming_coverage_reportable"] is False
        assert enough["summary"]["roaming_coverage_reportable"] is True
        # 이슈 발행 여부와 플래그가 같은 술어에서 나온다.
        assert [i for i in few["issues"] if i.get("category") == "관측"] == []
        assert len([i for i in enough["issues"] if i.get("category") == "관측"]) == 1
        for d in (few, enough):
            s = d["summary"]
            assert s["roaming_coverage_reportable"] == coverage_is_reportable(
                s["roaming_sta_log_matched"], s["roaming_pcap_visible_pct"])

    def test_reportable_flag_is_false_when_unmeasurable(self):
        """대조 0건이면 플래그도 False — 화면이 '측정불가'를 단정으로 바꾸지 않는다."""
        d = _diag([_seq(25.0, None, fnum=100 + i * 10) for i in range(5)])
        assert d["summary"]["roaming_coverage_reportable"] is False

    def test_long_warning_is_truncated_with_disclosure(self):
        """[Codex P2] 개수만 제한하면 IP를 전부 join하는 경고 한 건이 계약을 깬다.

        `station_log.py`의 "kern.log에 STA IP가 여러 개다(...)"는 발견한 모든 distinct
        IP를 넣고, 업로드는 호기 로그를 64MB까지 받는다.
        """
        from ai.prompts import PROMPT_MAX_WARNING_CHARS, _build_station_log_section

        ips = ", ".join(f"192.168.{a}.{b}" for a in range(6) for b in range(60))
        long_warn = f"kern.log에 STA IP가 여러 개다({ips}) — DHCP 재할당 가능성"
        assert len(long_warn) > 2000            # 픽스처 전제 확인
        out = "\n".join(_build_station_log_section({"stations": [
            self._station(warnings=[long_warn]),
        ]}))
        assert len(out) < PROMPT_MAX_WARNING_CHARS + 500
        # 잘랐다는 사실과 원래 길이를 숨기지 않는다.
        assert f"총 {len(long_warn)}자, 생략" in out


class TestPromptRendering:
    """AI 프롬프트 — 없는 데이터를 아는 척하지 않게 만드는 경고가 핵심."""

    def _prompt_roaming(self, seqs):
        from ai.prompts import _build_roaming_section

        return "\n".join(_build_roaming_section({"sequences": seqs}))

    def test_sta_total_stats_and_warning(self):
        lines = self._prompt_roaming([_seq(25.0, 97.0) for _ in range(5)])
        assert "sta_log.total_ms" in lines
        assert "97.0" in lines
        # 로그가 안 붙은 로밍을 '빨랐다'로 읽으면 안 된다.
        assert "모른다" in lines or "알 수 없" in lines

    def test_no_sta_log_no_block(self):
        lines = self._prompt_roaming([_seq(25.0, None) for _ in range(5)])
        assert "sta_log.total_ms" not in lines

    def test_station_log_section(self):
        from ai.prompts import _build_station_log_section

        out = "\n".join(_build_station_log_section({"stations": [{
            "name": "1호기", "sta_name": "STA2", "match_method": "ip",
            "attached": 281, "roam_total": 306, "total_ms_p50": 96.5,
            "scan_ms_p50": 61.7, "residual_mad_ms": 20.7, "warnings": [],
        }]}))
        assert "1호기" in out and "96.5" in out
        assert _build_station_log_section({}) == []
        assert _build_station_log_section({"stations": []}) == []
