"""웹 시각화 분석 모듈 테스트."""
from analyzer.core.indexer import FrameIndex
from analyzer.web.delay_analysis import analyze_delays
from analyzer.web.anomaly_frames import detect_anomalies
from analyzer.web.signal_cliff import analyze_signal_cliffs
from analyzer.web.evidence import (
    cliff_evidence,
    mcs_hotspot_evidence,
    network_legacy_evidence,
)
from tests.conftest import make_frame, SAMPLE_ROLES, STA1, AP1


class TestAnalyzeDelays:
    def test_empty_data(self):
        result = analyze_delays(
            {"pairs": [], "losses": []},
            {"sequences": []},
            {"timeline": []},
        )
        assert result["delay_zones"] == []
        assert result["summary"]["total_zones"] == 0

    def test_detects_high_rtt_zone(self):
        # 10 normal pings + 3 high RTT pings
        pairs = [{"epoch": 1000 + i, "rtt_ms": 5.0} for i in range(10)]
        pairs += [{"epoch": 1010 + i, "rtt_ms": 100.0} for i in range(3)]
        result = analyze_delays(
            {"pairs": pairs, "losses": []},
            {"sequences": []},
            {"timeline": []},
        )
        assert result["summary"]["total_zones"] >= 1

    def test_detects_loss_zone(self):
        pairs = [{"epoch": 1000 + i, "rtt_ms": 5.0} for i in range(5)]
        losses = [{"epoch": 1010.0}, {"epoch": 1011.0}]
        result = analyze_delays(
            {"pairs": pairs, "losses": losses},
            {"sequences": []},
            {"timeline": []},
        )
        assert result["summary"]["total_zones"] >= 1

    def test_roaming_cause_detection(self):
        pairs = [{"epoch": 1000 + i, "rtt_ms": 5.0} for i in range(10)]
        pairs += [{"epoch": 1010, "rtt_ms": 200.0}]
        roaming = {"sequences": [{"auth_epoch": 1010.5}]}
        result = analyze_delays(
            {"pairs": pairs, "losses": []},
            roaming,
            {"timeline": []},
        )
        zones = result["delay_zones"]
        if zones:
            assert zones[0]["cause"] == "roaming"


class TestDetectAnomalies:
    def test_empty(self):
        result = detect_anomalies({"total_frames": 0})
        assert result["anomalies"] == []

    def test_deauth_detected(self):
        result = detect_anomalies({
            "total_frames": 1000,
            "subtype_dist": {"12": 15},
            "protocol_dist": {},
        })
        anomalies = result["anomalies"]
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "deauth_disassoc"
        assert anomalies[0]["severity"] == "high"

    def test_excessive_probe_req(self):
        result = detect_anomalies({
            "total_frames": 100,
            "subtype_dist": {"4": 25},  # 25%
            "protocol_dist": {},
        })
        anomalies = result["anomalies"]
        types = [a["type"] for a in anomalies]
        assert "excessive_probe_req" in types

    def test_arp_storm(self):
        result = detect_anomalies({
            "total_frames": 100,
            "subtype_dist": {},
            "protocol_dist": {"ARP": 15},  # 15%
        })
        anomalies = result["anomalies"]
        types = [a["type"] for a in anomalies]
        assert "arp_storm" in types

    def test_no_anomalies_normal(self):
        result = detect_anomalies({
            "total_frames": 10000,
            "subtype_dist": {"40": 8000, "8": 1000},
            "protocol_dist": {"802.11": 9000},
        })
        assert len(result["anomalies"]) == 0


class TestSignalCliffs:
    def test_empty(self):
        result = analyze_signal_cliffs({"stas": {}})
        assert result == {}

    def test_no_cliff_stable_signal(self):
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -50, "mcs": 7} for i in range(20)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        assert result["STA1"]["cliffs"] == []

    def test_cliff_detected(self):
        # Stable at -50, then drop to -70
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -50, "mcs": 7} for i in range(15)]
        timeline += [{"epoch": 1001.5 + i * 0.1, "rssi": -70, "mcs": 3} for i in range(10)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        cliffs = result["STA1"]["cliffs"]
        assert len(cliffs) >= 1
        assert cliffs[0]["drop_db"] >= 10

    def test_moving_average_no_longer_emitted(self):
        # moving_avg는 소비자가 0건인데 RSSI 샘플당 dict를 만들어 대용량 캡처
        # 결과 JSON을 크게 부풀렸다 — 제거됐다.
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -55 + (i % 3), "mcs": 7} for i in range(25)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        assert "moving_avg" not in result["STA1"]

    def test_few_points_skipped(self):
        timeline = [{"epoch": 1000 + i, "rssi": -50, "mcs": 7} for i in range(5)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        assert result["STA1"]["cliffs"] == []
        assert "moving_avg" not in result["STA1"]

    def test_bucketed_timeline_keeps_cliff_sensitivity(self):
        # 1초 버킷 집계 시계열(structured._bucket_rssi_timeline 스키마)에서
        # 버킷 평균은 완만해도 버킷 내 최저(rssi_min)로 급락이 잡혀야 한다 —
        # 평균끼리만 비교하면 이 절벽은 통째로 사라진다(과소 탐지).
        timeline = [
            {"epoch": 1000 + i, "rssi": -50.0, "rssi_min": -51, "rssi_max": -49, "n": 100}
            for i in range(12)
        ]
        # 다음 초에 순간 -70까지 떨어졌지만 그 초의 평균은 -52에 불과하다.
        timeline.append(
            {"epoch": 1012, "rssi": -52.0, "rssi_min": -70, "rssi_max": -50, "n": 100}
        )
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        cliffs = result["STA1"]["cliffs"]
        assert len(cliffs) >= 1
        assert cliffs[0]["rssi_after"] == -70
        assert cliffs[0]["drop_db"] >= 10

    def test_legacy_raw_sample_timeline_still_supported(self):
        # 구버전 결과(rssi_min/rssi_max 없는 프레임당 원샘플)도 분기 없이 그대로
        # 판정된다 — serialized-result-backward-compat.
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -50, "mcs": 7} for i in range(15)]
        timeline += [{"epoch": 1001.5 + i * 0.1, "rssi": -70, "mcs": 3} for i in range(10)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        cliffs = result["STA1"]["cliffs"]
        assert len(cliffs) >= 1
        assert cliffs[0]["rssi_before"] == -50
        assert cliffs[0]["rssi_after"] == -70


class TestMcsHotspotEvidence:
    def _index(self, frames):
        return FrameIndex(frames, dict(SAMPLE_ROLES))

    def test_modern_phy_match(self):
        # HE MCS7 retry 프레임 3건 + 비매칭 프레임.
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, retry=True,
                       mcs="7", mcs_phy="HE"),
            make_frame(number=2, epoch=1001.0, ta=STA1, ra=AP1, retry=True,
                       mcs="7", mcs_phy="HE"),
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, retry=True,
                       mcs="7", mcs_phy="HE"),
            # 비매칭: 다른 MCS / non-retry / 다른 PHY.
            make_frame(number=4, epoch=1003.0, ta=STA1, ra=AP1, retry=True,
                       mcs="3", mcs_phy="HE"),
            make_frame(number=5, epoch=1004.0, ta=STA1, ra=AP1, retry=False,
                       mcs="7", mcs_phy="HE"),
        ]
        idx = self._index(frames)
        refs, window = mcs_hotspot_evidence(STA1, "HE", "7", frames, idx)
        assert set(refs) == {1, 2, 3}
        assert window == {"start_epoch": 1000.0, "end_epoch": 1002.0}

    def test_legacy_match(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, retry=True,
                       mcs="", mcs_phy="Legacy", data_rate="6"),
            make_frame(number=2, epoch=1001.0, ta=STA1, ra=AP1, retry=True,
                       mcs="", mcs_phy="", data_rate="6"),
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, retry=True,
                       mcs="", mcs_phy="Legacy", data_rate="54"),
        ]
        idx = self._index(frames)
        refs, window = mcs_hotspot_evidence(STA1, "Legacy", "6", frames, idx)
        assert set(refs) == {1, 2}
        assert window is not None

    def test_no_match_returns_empty(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, retry=False,
                       mcs="7", mcs_phy="HE"),
        ]
        idx = self._index(frames)
        assert mcs_hotspot_evidence(STA1, "HE", "7", frames, idx) == ([], None)


class TestCliffEvidence:
    def _index(self, frames):
        return FrameIndex(frames, dict(SAMPLE_ROLES))

    def test_frames_near_cliff(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1),
            make_frame(number=2, epoch=1000.5, ta=STA1, ra=AP1),
            make_frame(number=3, epoch=1005.0, ta=STA1, ra=AP1),  # 멀리
        ]
        idx = self._index(frames)
        cliffs = [{"epoch": 1000.2, "drop_db": 15}]
        refs, window = cliff_evidence(STA1, cliffs, frames, idx)
        assert set(refs) == {1, 2}
        assert window == {"start_epoch": 1000.2, "end_epoch": 1000.2}

    def test_empty_cliffs_returns_empty(self):
        frames = [make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1)]
        idx = self._index(frames)
        assert cliff_evidence(STA1, [], frames, idx) == ([], None)

    def test_fallback_to_lowest_rssi(self):
        # cliff epoch 근처(±1s)엔 프레임 없지만 worst cliff ±5s 안에 RSSI 프레임 존재.
        frames = [
            make_frame(number=1, epoch=1003.0, ta=STA1, ra=AP1, rssi="-80,-82"),
            make_frame(number=2, epoch=1004.0, ta=STA1, ra=AP1, rssi="-60,-62"),
        ]
        idx = self._index(frames)
        cliffs = [{"epoch": 1000.0, "drop_db": 20}]
        refs, window = cliff_evidence(STA1, cliffs, frames, idx)
        assert refs == [1]  # 최저 RSSI(-80) 프레임
        assert window == {"start_epoch": 1000.0, "end_epoch": 1000.0}


class TestNetworkLegacyEvidence:
    def test_collects_legacy_frames(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, mcs_phy="Legacy",
                       data_rate="6"),
            make_frame(number=2, epoch=1001.0, ta=STA1, ra=AP1, mcs_phy=""),
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, mcs_phy="HE", mcs="7"),
        ]
        idx = FrameIndex(frames, dict(SAMPLE_ROLES))
        refs, window = network_legacy_evidence(frames, idx)
        assert set(refs) == {1, 2}
        assert window == {"start_epoch": 1000.0, "end_epoch": 1001.0}

    def test_no_legacy_returns_empty(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, mcs_phy="HE", mcs="7"),
        ]
        idx = FrameIndex(frames, dict(SAMPLE_ROLES))
        assert network_legacy_evidence(frames, idx) == ([], None)


class TestIntraBucketCliff:
    """1초 버킷 안에서 시작하고 끝난 급락도 잡아야 한다.

    rssi_timeline이 1초 버킷 집계로 바뀌면서, 탐지 루프가 다음 버킷부터 비교하면
    같은 버킷 안에서 일어난 하락(멀티패스 순간 변동)은 어느 쌍과도 비교되지 않아
    통째로 사라진다 — 원샘플 시절에는 잡히던 하락이다. 버킷이 min/max를 함께
    담고 있으므로 자기 버킷의 max↔min을 비교하면 복원된다.
    """

    def _flat(self, n=12, rssi=-50):
        return [
            {"epoch": 1000 + i, "rssi": rssi, "rssi_min": rssi, "rssi_max": rssi}
            for i in range(n)
        ]

    def test_drop_inside_one_bucket_detected(self):
        # 주변을 -58로 깔아 **버킷 간** 하락이 어느 쌍에서도 10dB에 못 미치게 한다
        # (앞 버킷 max -58 → 급락 버킷 min -62 = 4dB, 급락 버킷 max -50 → 뒤 버킷
        # min -58 = 8dB). 오직 자기 버킷의 max↔min(12dB)만 임계를 넘는다.
        timeline = self._flat(rssi=-58)
        timeline[5] = {"epoch": 1005, "rssi": -56, "rssi_min": -62, "rssi_max": -50}
        cliffs = analyze_signal_cliffs(
            {"stas": {"STA1": {"rssi_timeline": timeline}}})["STA1"]["cliffs"]
        assert len(cliffs) == 1
        c = cliffs[0]
        assert c["epoch"] == 1005
        assert c["drop_db"] == 12          # 버킷 최대 -50 → 최소 -62
        assert c["duration_sec"] == 0.0    # 같은 버킷 = 1초 미만

    def test_intra_bucket_inside_reported_cliff_is_not_double_counted(self):
        """하강 도중의 버킷은 max-min이 크다 — 그대로 세면 절벽 하나를 반복해 센다."""
        timeline = self._flat()
        # 1005~1008에 걸쳐 -50 → -70으로 내려간다(각 버킷 안에서도 폭이 크다).
        for k, (hi, lo) in enumerate([(-50, -58), (-58, -66), (-66, -70)], start=5):
            timeline[k] = {"epoch": 1000 + k, "rssi": (hi + lo) // 2,
                           "rssi_min": lo, "rssi_max": hi}
        cliffs = analyze_signal_cliffs(
            {"stas": {"STA1": {"rssi_timeline": timeline}}})["STA1"]["cliffs"]
        spans = [(c["epoch"], c["duration_sec"]) for c in cliffs]
        # 구간 안쪽 버킷이 중복으로 잡히면 같은 시각대에 항목이 겹쳐 쌓인다.
        assert len(cliffs) == len({e for e, _ in spans}), spans

    def test_stable_buckets_still_report_nothing(self):
        cliffs = analyze_signal_cliffs(
            {"stas": {"STA1": {"rssi_timeline": self._flat()}}})["STA1"]["cliffs"]
        assert cliffs == []

    def test_legacy_raw_samples_unaffected(self):
        """구버전 result(원샘플)에는 min/max가 없어 판정이 달라지지 않아야 한다."""
        raw = [{"epoch": 1000 + i * 0.1, "rssi": -50, "mcs": 7} for i in range(20)]
        cliffs = analyze_signal_cliffs(
            {"stas": {"STA1": {"rssi_timeline": raw}}})["STA1"]["cliffs"]
        assert cliffs == []

    def test_cross_bucket_drop_still_detected(self):
        timeline = self._flat()
        for i in range(6, 12):
            timeline[i] = {"epoch": 1000 + i, "rssi": -66,
                           "rssi_min": -66, "rssi_max": -66}
        cliffs = analyze_signal_cliffs(
            {"stas": {"STA1": {"rssi_timeline": timeline}}})["STA1"]["cliffs"]
        assert cliffs and cliffs[0]["drop_db"] == 16


class TestReportLossBasis:
    """리포트 요약이 **판정에 쓴 값**과 그 근거를 드러내야 한다.

    유선 확정과 무선 관측이 다를 때 하나만 적으면 독자가 어느 쪽을 본 건지 모른다 —
    실측에서 유선 0.38% vs 무선 8.24%로 20배 차이가 난다.
    """

    def _section(self, summary):
        from analyzer.web.report import _health_section

        diag = {
            "health": {"score": 90, "grade": "양호"},
            "component_scores": {"retry": 90, "loss": 96, "roaming": 100},
            "summary": summary,
            "issues": [],
            "sta_diags": [],
        }
        return "\n".join(_health_section(diag))

    def test_wired_basis_shows_both_numbers(self):
        out = self._section({
            "retry_pct": 3, "loss_pct": 8.24,
            "loss_pct_used": 0.38, "loss_basis": "wired_gt",
        })
        assert "Ping Loss 0.38% (유선 확정)" in out
        assert "무선 관측 8.24%" in out, "커버리지 차이를 감추면 안 된다"

    def test_wireless_basis_labeled(self):
        out = self._section({
            "retry_pct": 3, "loss_pct": 8.24,
            "loss_pct_used": 8.24, "loss_basis": "wireless_observed",
        })
        assert "Ping Loss 8.24% (무선 관측)" in out
        assert "무선 관측 8.24%" not in out.replace("(무선 관측)", "")

    def test_legacy_result_without_basis(self):
        """구버전 result에는 loss_pct_used/loss_basis가 없다 — 기존처럼 찍혀야 한다."""
        out = self._section({"retry_pct": 3, "loss_pct": 8.24})
        assert "Ping Loss 8.24%" in out


class TestLossBasisVocabularyParity:
    """판정 근거 어휘가 Python·JS 양쪽에서 갈라지지 않는지 고정한다.

    JS는 Python 상수를 import할 수 없어 `charts.js`가 같은 키·라벨을 손으로 들고
    있다. 주석으로 안내는 했지만 강제 수단이 없으면 라벨을 한쪽만 고쳤을 때
    화면만 달라지는 **무음 회귀**가 된다 — 그 순간을 이 테스트가 잡는다.
    """

    def _js_map(self):
        import re
        from pathlib import Path

        src = Path("static/js/charts.js").read_text(encoding="utf-8")
        m = re.search(r"const LOSS_BASIS_LABEL = \{([^}]*)\}", src)
        assert m, "charts.js에서 LOSS_BASIS_LABEL 정의를 찾지 못했다"
        return dict(re.findall(r"(\w+)\s*:\s*'([^']*)'", m.group(1)))

    def test_keys_and_labels_match_python(self):
        from analyzer.web.structured import LOSS_BASIS_LABELS

        assert self._js_map() == LOSS_BASIS_LABELS

    def test_report_uses_the_same_labels(self):
        """report.py도 같은 정의를 쓰는지 — 자체 dict로 갈라진 적이 있다."""
        import inspect

        from analyzer.web import report

        src = inspect.getsource(report._health_section)
        assert "LOSS_BASIS_LABELS" in src
        assert '"유선 확정"' not in src and '"무선 관측"' not in src
