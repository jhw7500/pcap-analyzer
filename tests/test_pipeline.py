"""pipeline 구조화 함수 테스트."""

from tests.conftest import make_frame, AP1, STA1, SAMPLE_ROLES
from analyzer.core.indexer import FrameIndex
from analyzer.pipeline import (
    _structured_overview,
    _structured_signal,
    _structured_ping,
    _structured_roaming,
    _structured_per_second,
    _structured_device_stats,
    _structured_diagnosis,
)
from analyzer.casefile_builder import build_casefile


def _build(frames, roles=None):
    roles = roles or SAMPLE_ROLES
    index = FrameIndex(frames, roles)
    return frames, roles, index


class TestStructuredOverview:
    def test_empty(self):
        result = _structured_overview([], {}, None)
        assert result["total_frames"] == 0

    def test_normal(self, sample_frames, sample_roles):
        result = _structured_overview(sample_frames, sample_roles, None)
        assert result["total_frames"] == 10
        assert result["duration_sec"] > 0
        assert "protocol_dist" in result
        assert "devices" in result


class TestStructuredSignal:
    def test_with_stas(self):
        frames = [
            make_frame(number=i, epoch=1000 + i, ta=STA1, ra=AP1, rssi=f"{-55 - i}")
            for i in range(10)
        ]
        f, r, idx = _build(frames)
        result = _structured_signal(f, r, idx)
        assert "STA1(0002)" in result["stas"]
        sta = result["stas"]["STA1(0002)"]
        assert sta["rssi_avg"] is not None
        assert sta["frame_count"] > 0

    def test_no_sta_frames(self):
        # STA가 있지만 RSSI 프레임이 없는 경우
        frames = [make_frame(number=1, epoch=1000, ta=AP1, ra=STA1, rssi="")]
        f, r, idx = _build(frames)
        result = _structured_signal(f, r, idx)
        for sta_info in result["stas"].values():
            assert sta_info["frame_count"] == 0 or sta_info["rssi_avg"] is None


class TestStructuredPing:
    def test_matched_pair(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 1
        assert len(result["losses"]) == 0
        assert result["stats"]["count"] == 1

    def test_unmeasurable_when_unidirectional(self):
        # 단방향 캡처: request만 있고 짝꿍 reply 흐름이 없음 → 무선 손실로 단정 불가
        # → losses=0, unmeasurable=1 로 분류 (loss로 보고하지 않음)
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["losses"]) == 0
        assert len(result["pairs"]) == 0
        assert result["stats"]["unmeasurable_count"] == 1
        assert result["stats"]["capture_mode"] == "unidirectional"

    def test_loss_when_bidirectional_unmatched(self):
        # 양방향 캡처에서 reply 없는 request → 확정 loss
        frames = [
            make_frame(
                number=1, epoch=1000, icmp_type="8",
                ip_src="10.0.0.1", ip_dst="10.0.0.2",
                icmp_seq="1", ta=STA1, ra=AP1,
            ),
            # 같은 흐름(=swap된 src/dst + 같은 ident)에 reply가 하나라도 있으면 양방향 인식
            make_frame(
                number=2, epoch=1000.5, icmp_type="0",
                ip_src="10.0.0.2", ip_dst="10.0.0.1",
                icmp_seq="2", ta=AP1, ra=STA1,
            ),
            # seq=1에 대한 reply는 없음 → 확정 loss
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["losses"]) == 1
        assert len(result["pairs"]) == 0
        assert result["stats"]["capture_mode"] == "bidirectional"

    def test_bidi_reply_missing_is_confirmed_loss(self):
        # 양방향 흐름에서 req(seq=1)는 있고 같은 seq의 reply는 없음 → 확정 무선 손실
        frames = [
            make_frame(number=1, epoch=1000, icmp_type="8",
                       ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_seq="1"),
            make_frame(number=2, epoch=1001, icmp_type="8",
                       ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_seq="2"),
            make_frame(number=3, epoch=1001.01, icmp_type="0",
                       ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_seq="2"),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert result["stats"]["reply_missing"] == 1  # seq=1
        assert result["stats"]["verified_cycle"] == 1  # seq=2
        assert len(result["pairs"]) == 1  # seq=2 매칭됨
        # losses 에는 seq=1의 req entry가 들어가야 함
        assert any(L["seq"] == "1" for L in result["losses"])

    def test_bidi_request_missing_is_capture_issue_not_loss(self):
        # reply(seq=1)만 보이고 같은 seq의 req가 없음 → 캡처 누락 (무선 OK)
        # 양방향으로 인식되려면 같은 흐름에 req 1건 이상 필요
        frames = [
            make_frame(number=1, epoch=1000, icmp_type="8",
                       ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_seq="2"),
            make_frame(number=2, epoch=1000.01, icmp_type="0",
                       ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_seq="2"),
            # seq=1 reply만 있고 그에 대응하는 req는 캡처에 없음
            make_frame(number=3, epoch=999.5, icmp_type="0",
                       ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_seq="1"),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert result["stats"]["request_missing"] == 1
        assert result["stats"]["reply_missing"] == 0
        # 캡처 누락된 reply는 observations로 노출
        assert any(o["seq"] == "1" and o["direction"] == "reply" for o in result["observations"])

    def test_seq_gap_detected_as_loss_in_unidirectional(self):
        # 단방향이라도 흐름 안의 seq 갭은 진짜 무선 손실로 잡힘 (seq=2 누락)
        frames = [
            make_frame(number=1, epoch=1000, icmp_type="8",
                       ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_seq="1"),
            make_frame(number=2, epoch=1001, icmp_type="8",
                       ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_seq="3"),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert result["stats"]["seq_gap_losses"] == 1
        assert len(result["losses"]) == 1
        assert result["losses"][0]["seq"] == "2"
        assert result["losses"][0]["status"] == "loss_gap"

    def test_empty(self):
        result = _structured_ping([], SAMPLE_ROLES)
        assert result["full_list"] == []

    def test_seq_reuse_time_window(self):
        # 동일 (src,dst,seq)를 1분 간격으로 재사용 — 각각 매칭되어야 함
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
            # 60초 뒤 seq=1 재사용
            make_frame(
                number=3,
                epoch=1060,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=4,
                epoch=1060.010,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 2
        assert len(result["losses"]) == 0
        # RTT 차이 확인 (5ms, 10ms)
        rtts = sorted(p["rtt_ms"] for p in result["pairs"])
        assert rtts[0] == 5.0
        assert rtts[1] == 10.0

    def test_request_outside_window_no_rtt_but_not_loss(self):
        # req와 reply가 30초 초과 떨어짐 → RTT 매칭은 실패하지만
        # 양쪽 seq=99가 모두 관측됐으므로 무선 손실은 아님 (verified_cycle).
        # Phase 2b 교차 검증의 핵심 의미: "reply가 시간상 너무 늦게 와도
        # 캡처에는 존재함" 은 진짜 무선 손실로 단정할 수 없음.
        frames = [
            make_frame(
                number=1, epoch=1000, icmp_type="8",
                ip_src="10.0.0.1", ip_dst="10.0.0.2",
                icmp_seq="99", ta=STA1, ra=AP1,
            ),
            make_frame(
                number=2, epoch=1031, icmp_type="0",
                ip_src="10.0.0.2", ip_dst="10.0.0.1",
                icmp_seq="99", ta=AP1, ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 0  # RTT 매칭은 윈도우 초과로 실패
        assert len(result["losses"]) == 0  # 무선 손실 아님 (양쪽 다 관측됨)
        assert result["stats"]["verified_cycle"] == 1
        assert result["stats"]["reply_missing"] == 0
        assert result["stats"]["capture_mode"] == "bidirectional"

    def test_duplicate_reply_only_first_matches(self):
        # 하나의 req에 reply 2개 → 첫 번째만 매칭
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="7",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="7",
                ta=AP1,
                ra=STA1,
            ),
            make_frame(
                number=3,
                epoch=1000.010,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="7",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 1
        assert result["pairs"][0]["reply_num"] == 2  # 첫 reply만

    def test_reply_without_request_ignored(self):
        # reply만 있고 대응 req 없음
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="5",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 0
        assert len(result["losses"]) == 0

    def test_no_seq_uses_fifo_fallback(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 1
        assert len(result["losses"]) == 0


class TestStructuredRoaming:
    def test_sequence(self):
        frames = [
            make_frame(number=1, epoch=1000, ta=STA1, ra=AP1, subtype="11"),  # Auth
            make_frame(
                number=2, epoch=1000.05, ta=STA1, ra=AP1, subtype="0"
            ),  # AssocReq
        ]
        result = _structured_roaming(frames, SAMPLE_ROLES)
        assert len(result["sequences"]) == 1
        assert result["sequences"][0]["gap_ms"] > 0

    def test_empty(self):
        result = _structured_roaming([], SAMPLE_ROLES)
        assert result["sequences"] == []


class TestStructuredPerSecond:
    def test_timeline(self):
        frames = [make_frame(number=i, epoch=1000 + i) for i in range(5)]
        result = _structured_per_second(frames)
        assert len(result["timeline"]) == 5

    def test_empty(self):
        result = _structured_per_second([])
        assert result["timeline"] == []


class TestStructuredDeviceStats:
    def test_stats(self, sample_frames, sample_roles, sample_index):
        result = _structured_device_stats(sample_frames, sample_roles, sample_index)
        assert len(result) > 0
        for name, stats in result.items():
            assert "total_frames" in stats
            assert "retry_pct" in stats


class TestStructuredDiagnosis:
    def test_health_score(self):
        structured = {
            "overview": {"total_frames": 1000, "retry_pct": 5},
            "ping": {"stats": {"loss_pct": 2}},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "device_stats": {},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        result = _structured_diagnosis(structured)
        assert result["health"]["score"] > 0
        assert result["health"]["grade"] in ("양호", "주의", "위험")

    def _problem_capture(self):
        """retry 폭증 + ping loss + 느린 로밍을 모두 자극하는 frames + structured."""
        frames = []
        n = 1
        # 네트워크 retry 폭증: STA1 송신 retry 프레임 200건 (한 10초 버킷)
        for i in range(200):
            frames.append(make_frame(
                number=n, epoch=2000.0 + i * 0.01, ta=STA1, ra=AP1,
                subtype="40", retry=True,
            ))
            n += 1
        # 손실 ping request 프레임 (req_num으로 근거)
        loss_frames = []
        for i in range(6):
            f = make_frame(
                number=n, epoch=2100.0 + i, ta=STA1, ra=AP1,
                icmp_type="8", ip_src="10.0.0.2", ip_dst="10.0.0.1",
                icmp_seq=str(i + 1),
            )
            frames.append(f)
            loss_frames.append(f)
            n += 1
        # 느린 로밍 시퀀스 6건 (auth/assoc fnum + epoch 근거)
        sequences = []
        for i in range(6):
            auth = make_frame(number=n, epoch=2200.0 + i * 2, ta=STA1, ra=AP1, subtype="11")
            frames.append(auth)
            n += 1
            assoc = make_frame(number=n, epoch=2200.5 + i * 2, ta=STA1, ra=AP1, subtype="2")
            frames.append(assoc)
            n += 1
            sequences.append({
                "sta": STA1, "ap": AP1,
                "auth_epoch": auth.epoch, "assoc_epoch": assoc.epoch,
                "auth_fnum": auth.number, "assoc_fnum": assoc.number,
                "is_slow": True,
            })
        index = FrameIndex(frames, SAMPLE_ROLES)
        structured = {
            "overview": {"total_frames": len(frames), "retry_pct": 30},
            "ping": {
                "stats": {"loss_pct": 15},
                "losses": [
                    {"req_num": f.number, "epoch": f.epoch, "seq": f.icmp_seq}
                    for f in loss_frames
                ],
            },
            "roaming": {"sequences": sequences},
            "signal": {"stas": {}},
            "device_stats": {},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        return structured, frames, index

    def test_issues_sorted_by_severity(self):
        structured, frames, index = self._problem_capture()
        result = _structured_diagnosis(structured, frames, index)
        issues = result["issues"]
        assert len(issues) > 0
        # high가 medium보다 먼저
        severities = [i["severity"] for i in issues]
        if "high" in severities and "medium" in severities:
            assert severities.index("high") < severities.index("medium")

    def test_every_issue_has_frame_refs_and_time_window(self):
        """AC1: 모든 진단 결론(issues/sta_diags issues)이 근거+time_window 동반."""
        structured, frames, index = self._problem_capture()
        result = _structured_diagnosis(structured, frames, index)

        assert result["issues"], "문제 캡처에서 issue가 생성되어야 한다"
        for iss in result["issues"]:
            assert iss.get("frame_refs"), f"근거 없는 issue: {iss['msg']!r}"
            assert all(isinstance(n, int) for n in iss["frame_refs"])
            tw = iss.get("time_window")
            assert tw is not None, f"time_window 없는 issue: {iss['msg']!r}"
            assert tw["end_epoch"] >= tw["start_epoch"]
            # frame_refs 상한 (대용량 캡처 안전)
            assert len(iss["frame_refs"]) <= 100

        for sd in result["sta_diags"]:
            for iss in sd["issues"]:
                assert iss.get("frame_refs"), f"근거 없는 STA issue: {iss['msg']!r}"
                assert iss.get("time_window") is not None

    def test_debug_block_is_bounded_and_grounded(self):
        """AC6: build_debug_block은 공유 축+다운샘플 시계열+근거 프레임을 bounded로."""
        from analyzer.web.evidence import build_debug_block, DEBUG_FRAME_CAP

        structured, frames, index = self._problem_capture()
        structured["per_second"] = {
            "timeline": [
                {"epoch": int(f.epoch), "total": 1, "retry": 1 if f.retry else 0}
                for f in frames
            ]
        }
        structured["diagnosis"] = _structured_diagnosis(structured, frames, index)
        debug = build_debug_block(structured, frames, index)

        assert "axis" in debug and "series" in debug and "frames" in debug
        assert set(debug["series"]) == {"rssi", "retry", "ping", "roaming"}
        assert len(debug["frames"]) <= DEBUG_FRAME_CAP
        # 디버그 프레임은 표시용 8개 컬럼을 모두 노출(+ 동기화용 보조 epoch)
        if debug["frames"]:
            from analyzer.web.frame_table import FRAME_ROW_KEYS
            assert set(FRAME_ROW_KEYS).issubset(debug["frames"][0])
            assert "epoch" in debug["frames"][0]
        # 모든 finding 근거 frame_number가 debug.frames에 포함됨
        debug_nums = {row["number"] for row in debug["frames"]}
        for iss in structured["diagnosis"]["issues"]:
            assert set(iss["frame_refs"]) & debug_nums, (
                f"근거 프레임이 debug 블록에 누락: {iss['msg']!r}"
            )

    def test_retry_evidence_includes_downlink_retries(self):
        """U1 회귀: retry_pct는 by_ta(TX)+by_ra(RX) 양쪽으로 계산되므로,
        다운링크(by_ra) retry만 있는 STA도 retry_bucket_evidence가 근거를
        반환해야 한다. by_ta만 보면 결론이 근거 없음으로 드롭됐다(regression)."""
        from analyzer.web.evidence import retry_bucket_evidence

        # STA1은 송신(by_ta) retry 0건; AP가 STA1에게 보낸(by_ra) retry만 존재
        frames = [
            make_frame(number=i + 1, epoch=2000.0 + i, ta=AP1, ra=STA1,
                       subtype="40", retry=True)
            for i in range(10)
        ]
        index = FrameIndex(frames, SAMPLE_ROLES)
        refs, window = retry_bucket_evidence(STA1, index)
        assert refs, "다운링크 retry 프레임이 근거로 잡혀야 한다"
        assert window is not None and window["end_epoch"] >= window["start_epoch"]

    def test_ping_loss_evidence_uses_anchor_for_loss_gap(self):
        """U4 회귀: loss_gap(req_num=None)도 anchor_num을 frame_ref로 사용해
        ping loss 결론이 근거 없음으로 드롭되지 않아야 한다(regression)."""
        from analyzer.web.evidence import ping_loss_evidence

        losses = [
            {"req_num": None, "anchor_num": 77, "epoch": 1000.0,
             "status": "loss_gap"},
        ]
        refs, window = ping_loss_evidence(losses)
        assert refs == [77]
        assert window is not None and window["start_epoch"] == 1000.0

    def test_debug_block_preserves_all_cited_frames_over_cap(self):
        """U3 회귀: cited 근거 frame(ref_set)이 DEBUG_FRAME_CAP을 넘어도
        다운샘플로 드롭되지 않아야 한다. 모든 finding이 최소 1개 근거를 보존해
        '증거 보기' grounding 불변식을 지킨다."""
        from analyzer.web.evidence import build_debug_block, DEBUG_FRAME_CAP

        total = DEBUG_FRAME_CAP + 500
        frames = [make_frame(number=i + 1, epoch=1000.0 + i) for i in range(total)]
        index = FrameIndex(frames, SAMPLE_ROLES)
        issues = []
        for start in range(0, total, 100):  # finding당 100 refs → ref_set > cap
            chunk = frames[start:start + 100]
            issues.append({
                "severity": "high", "category": "test",
                "msg": f"issue {start}", "action": "x",
                "frame_refs": [f.number for f in chunk],
                "time_window": {"start_epoch": chunk[0].epoch,
                                "end_epoch": chunk[-1].epoch},
            })
        structured = {
            "diagnosis": {"issues": issues, "sta_diags": []},
            "signal": {"stas": {}, "aps": {}},
            "ping": {"full_list": []},
            "roaming": {"sequences": []},
            "per_second": {"timeline": []},
        }
        debug = build_debug_block(structured, frames, index)
        debug_nums = {row["number"] for row in debug["frames"]}
        for iss in issues:
            assert set(iss["frame_refs"]) & debug_nums, (
                f"cited frame 전부 드롭됨: {iss['msg']!r}"
            )

    def test_debug_block_retry_series_is_per_frame(self):
        """U2 회귀: retry series는 per-frame으로 집계되어 retry_pct가 정상
        범위(≤100)여야 한다. per_second 집계를 per-frame 함수에 그대로 넣던
        버그에선 retry_pct가 수천 %까지 치솟았다."""
        from analyzer.web.evidence import build_debug_block

        frames = [
            make_frame(number=i + 1, epoch=1000.0 + i * 0.1, ta=STA1, ra=AP1,
                       subtype="40", retry=(i % 2 == 0))
            for i in range(100)
        ]
        index = FrameIndex(frames, SAMPLE_ROLES)
        structured = {
            "diagnosis": {"issues": [], "sta_diags": []},
            "signal": {"stas": {}, "aps": {}},
            "ping": {"full_list": []},
            "roaming": {"sequences": []},
            # per_second 집계가 있어도 retry series는 per-frame을 써야 한다
            "per_second": {"timeline": [{"epoch": 1000, "total": 100, "retry": 50}]},
        }
        debug = build_debug_block(structured, frames, index)
        assert debug["series"]["retry"], "retry series가 생성되어야 한다"
        for pt in debug["series"]["retry"]:
            assert pt["retry_pct"] <= 100.0, f"retry_pct 왜곡: {pt['retry_pct']}"
            assert pt["total"] >= pt["retry"]


class TestCasefileBuilder:
    def test_casefile_ping_parity_exact(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
            make_frame(
                number=3,
                epoch=1001.0,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="2",
                ta=STA1,
                ra=AP1,
            ),
        ]
        structured_ping = _structured_ping(frames, SAMPLE_ROLES)
        result = {
            "id": "test-analysis",
            "pcap_name": "test.pcap",
            "structured": {
                "overview": {"total_frames": 3, "retry_pct": 0},
                "ping": structured_ping,
            },
            "text_sections": [],
        }

        casefile = build_casefile(result)

        assert casefile["analysis_id"] == "test-analysis"
        assert casefile["schema_version"] == "1.0"
        assert casefile["generator_version"] == "casefile-v1"
        assert casefile["incident_id"].startswith("test-analysis:")
        assert casefile["ping"]["full_list"] == structured_ping["full_list"]
        assert casefile["ping"]["pairs"] == structured_ping["pairs"]
        assert casefile["ping"]["losses"] == structured_ping["losses"]

    def test_casefile_requires_timeout_loss(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
        ]
        structured_ping = _structured_ping(frames, SAMPLE_ROLES)
        result = {
            "id": "test-analysis",
            "pcap_name": "test.pcap",
            "structured": {
                "overview": {"total_frames": 2, "retry_pct": 0},
                "ping": structured_ping,
                "per_second": {"timeline": []},
                "roaming": {"sequences": []},
            },
            "text_sections": [],
        }

        import pytest

        with pytest.raises(ValueError):
            build_casefile(result)
