"""wired_ping.build_ground_truth — 유선 pcap ping ground truth 빌더."""
import datetime as dt
import shutil
import threading
import time
from pathlib import Path

import pytest

from analyzer.core import exping, wired_ping
from analyzer.core.exping import Exchange

#: 실경로(real capinfos subprocess) 테스트용 — scapy로 합성된 deterministic pcap.
#: 생성 스크립트(tests/fixtures/generate_sample_basic.py)의 BASE_EPOCH=1700000000.0
#: 기준, 실제 마지막 패킷 epoch은 capinfos 실측으로 확인(1700000001.703).
FIXTURE = Path(__file__).parent / "fixtures" / "sample_basic.pcap"


def _fake_tshark(tmp_path, body: str) -> str:
    """TSV를 뱉는 가짜 tshark 실행파일 (tests/test_exping.py 패턴)."""
    fake = tmp_path / "fake-tshark"
    fake.write_text("#!/bin/sh\n" + body)
    fake.chmod(0o755)
    return str(fake)


def _local_epoch(s: str) -> float:
    """테스트 전용 — build_ground_truth._parse_local_epoch와 동일 규칙(로컬 tz)."""
    return dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()


#: 요청 3건 중 가운데 1건 무응답 픽스처 (test_counts_ok_ng_and_loss_pct와
#: test_exchanges_and_rtt_stats_exposed에서 공유)
_BODY_OK = (
    "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
    "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 무응답
    "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
    "printf '102.003\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t3\\t\\n'\n"
)


def test_counts_ok_ng_and_loss_pct(tmp_path):
    """요청 3건 중 가운데 1건 무응답 → total 3 / ok 2 / ng 1 / 33.33%."""
    body = _BODY_OK
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 3 and gt["ok"] == 2 and gt["ng"] == 1
    assert gt["loss_pct"] == pytest.approx(33.33)
    assert gt["sender"] == "10.0.0.1"
    assert gt["targets"] == {
        "10.0.0.2": {"total": 3, "ng": 1, "late": 0, "unanswered": 1}
    }
    assert gt["ng_epochs"] == [101.0]
    assert gt["trailing_dropped"] == 0


def test_streaks_grouped_per_target(tmp_path):
    """NG 3연속(간격 1초) → streak 1개 count 3. 단독 NG는 streak 아님(min_len 2)."""
    body = (
        # 성공 1건으로 시작 (꼬리 제거 회피용 앵커는 마지막에 둔다)
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        # NG 3연속
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
        "printf '103.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t4\\t\\n'\n"
        # 5초 뒤 단독 NG 1건
        "printf '108.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t5\\t\\n'\n"
        # 마지막은 성공 — 꼬리 무응답 제거가 NG를 지우지 않게
        "printf '109.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t6\\t\\n'\n"
        "printf '109.001\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t6\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert gt["ng"] == 4
    assert len(gt["streaks"]) == 1
    st = gt["streaks"][0]
    assert st["target"] == "10.0.0.2"
    assert st["start_epoch"] == pytest.approx(101.0)
    assert st["end_epoch"] == pytest.approx(103.0)
    assert st["count"] == 3
    assert st["duration_sec"] == pytest.approx(2.0)


def test_late_reply_is_timeout_but_separate_from_unanswered(tmp_path):
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '101.5\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        "printf '102.1\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body), reply_timeout=1.0
    )
    assert gt["total"] == 2
    assert gt["ok"] == 1
    assert gt["ng"] == 1
    assert gt["late_count"] == 1
    assert gt["unanswered_count"] == 0
    assert gt["reply_timeout_sec"] == 1.0
    assert gt["exchanges"][0]["rtt_ms"] is None
    assert gt["exchanges"][0]["late_rtt_ms"] == pytest.approx(1500.0)
    # 기존 rtt_stats는 정상 응답만이라는 직렬화 계약을 유지한다. 신규 관측
    # 통계는 실제로 수신한 정상+지연 응답을 모두 포함해 화면 요약과 trace가
    # 서로 모순되지 않게 한다.
    assert gt["rtt_stats"] == {
        "n": 1, "min_ms": 100.0, "avg_ms": 100.0,
        "max_ms": 100.0, "p95_ms": 100.0,
    }
    assert gt["observed_rtt_stats"] == {
        "n": 2, "min_ms": 100.0, "avg_ms": 800.0,
        "max_ms": 1500.0, "p95_ms": 1500.0,
    }


def test_timeout_aware_wired_chart_uses_observed_rtts():
    """유선 KPI와 히스토그램이 지연 응답을 관측 RTT 모집단에 포함한다."""
    from pathlib import Path

    src = Path("static/js/charts.js").read_text(encoding="utf-8")
    assert "gt.observed_rtt_stats || gt.rtt_stats" in src
    assert "e.rtt_ms ?? e.late_rtt_ms" in src
    assert "Ping Timeout/NG" in src


def test_timeout_aware_wired_chart_relabels_streaks():
    """지연 응답도 포함한 유선 streak를 물리 손실이라고 표시하지 않는다."""
    from pathlib import Path

    src = Path("static/js/charts.js").read_text(encoding="utf-8")
    template = Path("templates/analysis.html").read_text(encoding="utf-8")
    assert "compareTimeout ? '연속 Timeout/NG 구간' : '연속 손실 구간'" in src
    assert "const streakKind = gt?.reply_timeout_sec != null ? 'Timeout/NG' : '손실';" in src
    assert 'id="ping-streak-description"' in template
    assert "인접 Timeout/NG 간격 ≤2초" in src


def test_wired_loss_marker_scales_against_late_rtts():
    """무응답 X 마커가 초 단위 지연 응답 아래에 묻히지 않는다."""
    from pathlib import Path

    src = Path("static/js/charts.js").read_text(encoding="utf-8")
    assert "e.rtt_ms ?? e.late_rtt_ms ?? 0" in src


def test_trailing_unanswered_dropped_with_warning(tmp_path, monkeypatch):
    """캡처 끝이 **확인된** 경우, 그 끝에 붙은 꼬리 무응답은 NG로 세지 않는다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 꼬리 무응답
    )
    # capinfos로 캡처 끝(101.2)이 확인된 경우에만 drop한다 — threshold=100.2라
    # 101.0 요청은 응답이 도착할 물리적 기회가 없었다.
    monkeypatch.setattr(wired_ping, "_detect_capture_end", lambda *a, **kw: 101.2)
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert gt["total"] == 1 and gt["ng"] == 0
    assert gt["trailing_dropped"] == 1
    assert any("꼬리" in w for w in gt["warnings"])
    assert len(gt["exchanges"]) == gt["total"]  # 꼬리 제외분은 exchanges에도 없다


def test_wireless_capture_returns_error(tmp_path):
    """무선(802.11) 캡처는 exping 가드가 거부 → error dict로 변환."""
    body = (
        "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t2\\n'\n"
        "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t2\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "무선" in gt["error"]


def test_missing_tshark_returns_error():
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path="/nonexistent/tshark-xyz")
    assert "tshark" in gt["error"]


def test_invalid_reply_timeout_rejected_before_tshark():
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path="/nonexistent/tshark-xyz", reply_timeout=0
    )
    assert "Ping timeout" in gt["error"]


def test_all_requests_unanswered_100_loss(tmp_path, monkeypatch):
    """요청 3건 전부 무응답이고 전부 capture_end 근접(reply_timeout 이내)이면
    캡처 절단인지 100% 손실인지 구분할 수 없어 전부 물리적 꼬리로 제외되고
    '응답 있는 요청이 하나도 없다' 에러가 된다 (PR #22 3라운드: capture_end
    기준 꼬리 판정으로 재구성 — 근거는 test_capture_end_aware_tail_* 참조)."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.1\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        "printf '100.2\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
    )
    # capture_end=100.5 → threshold=99.5(기본 reply_timeout=1.0) → 세 요청
    # (100.0/100.1/100.2) 모두 threshold보다 뒤라 전부 물리적 꼬리로 제외된다.
    monkeypatch.setattr(wired_ping, "_detect_capture_end", lambda *a, **kw: 100.5)
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" in gt
    assert "응답 있는" in gt["error"]  # 요청이 있었지만 응답이 없다는 뜻
    assert "3건" in gt["error"]  # dropped 건수 포함


def test_no_icmp_returns_error(tmp_path):
    """ICMP echo request가 없으면 pick_sender ValueError → error dict."""
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, ":\n"))
    assert "error" in gt


# --------------------------------------------------------------------------
# 시간/IP 필터 (PR #22 리뷰 반영 — 무선 extract_frames()와 대칭)
# --------------------------------------------------------------------------


def test_time_filter_excludes_requests_outside_window(tmp_path):
    """time_start 이전 요청은 필터 밖 — total에서 제외된다."""
    before = _local_epoch("2026-01-01 09:59:50")
    inside1 = _local_epoch("2026-01-01 10:00:05")
    inside2 = _local_epoch("2026-01-01 10:00:06")
    body = (
        f"printf '{before}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{before + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{inside1}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{inside1 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
        f"printf '{inside2}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
        f"printf '{inside2 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t3\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_start="2026-01-01 10:00:00",
    )
    assert "error" not in gt
    assert gt["total"] == 2 and gt["ng"] == 0


def test_time_filter_end_excludes_requests_after_window(tmp_path):
    """time_end 이후 요청은 필터 밖."""
    inside = _local_epoch("2026-01-01 10:00:05")
    after = _local_epoch("2026-01-01 10:01:00")
    body = (
        f"printf '{inside}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{inside + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{after}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{after + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:01:00",
    )
    assert "error" not in gt
    assert gt["total"] == 1


def test_ip_filter_narrows_targets_when_sender_also_listed(tmp_path):
    """ip_filter에 sender와 target을 함께 주면, exchange 단계의 'sender가
    필터에 있으면 전체 유지' 규칙이 적용돼 target만으로 좁혀지지 않고 전체가
    유지된다(무선 ip.addr==의 대칭 규칙 그대로 — sender in ips일 때의 동작)."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        f"printf '{t0}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 1}\\t10.0.0.1\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{t0 + 1.002}\\t10.0.0.3\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.1,10.0.0.3",
    )
    assert "error" not in gt
    assert gt["total"] == 2


def test_ip_filter_target_only_selects_matching_sender_and_narrows(tmp_path):
    """ip_filter에 target IP만 줘도(무선 ip.addr==와 대칭으로 dst도 봄) 그
    target에 ping하는 호스트가 sender로 선정되고, 이후 exchange 단계에서
    그 target 흐름만 남는다 — round-1 의미 복원(3라운드에서 src만 보도록
    바꿔 한때 깨졌던 부분 정정, team-lead 지시)."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        f"printf '{t0}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 1}\\t10.0.0.1\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{t0 + 1.002}\\t10.0.0.3\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.3",
    )
    assert "error" not in gt
    assert gt["sender"] == "10.0.0.1"
    assert gt["total"] == 1
    assert gt["targets"] == {
        "10.0.0.3": {"total": 1, "ng": 0, "late": 0, "unanswered": 0}
    }


def test_ip_filter_keeps_all_when_sender_listed(tmp_path):
    """무선 ip.addr==의 대칭: sender가 필터에 있으면 전체 유지(필터링 없음과 동일)."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        f"printf '{t0}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 1}\\t10.0.0.1\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{t0 + 1.002}\\t10.0.0.3\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.1",
    )
    assert "error" not in gt
    assert gt["total"] == 2


def test_unparseable_time_filter_returns_error(tmp_path):
    """파싱 불가 시간 문자열은 조용히 전체 구간을 쓰지 않고 명시적 error를 낸다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_start="not-a-date",
    )
    assert "error" in gt
    assert "시간 필터" in gt["error"] and "not-a-date" in gt["error"]


def test_filter_leaves_no_exchanges_returns_specific_error(tmp_path):
    """필터로 exchanges가 전부 걸러지면 '요청 없음'과 다른 전용 에러를 낸다."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        f"printf '{t0}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.99",
    )
    assert "error" in gt
    assert "필터 구간" in gt["error"]


# --------------------------------------------------------------------------
# 꼬리 무응답 제거 순서 (PR #22 2라운드 리뷰 — 필터 이전에 전체 캡처 기준으로
# 수행해야 창 안 마지막 자리의 진짜 손실을 "꼬리"로 오인하지 않는다)
# --------------------------------------------------------------------------


def test_time_filter_end_does_not_misclassify_real_loss_as_trailing(tmp_path):
    """time_end로 창을 자를 때, 창 안 마지막 무응답은 물리적 꼬리가 아니라
    진짜 손실이면 ng로 집계돼야 한다(캡처는 그 뒤로도 계속되고 응답이 있다)."""
    t1 = _local_epoch("2026-01-01 10:00:00")   # A: 응답 있음
    t2 = _local_epoch("2026-01-01 10:00:05")   # B: 응답 없음(진짜 손실) — 창 안 마지막
    t3 = _local_epoch("2026-01-01 10:01:00")   # C: 응답 있음, 창 밖(필터로 제외)
    body = (
        f"printf '{t1}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t1 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{t2}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{t3}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
        f"printf '{t3 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t3\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:00:30",
    )
    assert "error" not in gt
    assert gt["total"] == 2 and gt["ok"] == 1 and gt["ng"] == 1
    assert gt["trailing_dropped"] == 0
    assert not any("꼬리" in w for w in gt["warnings"])


def test_physical_trailing_still_dropped_with_filter_active(tmp_path, monkeypatch):
    """필터가 활성이어도 캡처 전체의 진짜(물리적) 꼬리 무응답은 여전히 제외된다."""
    t1 = _local_epoch("2026-01-01 10:00:00")   # A: 응답 있음
    t2 = _local_epoch("2026-01-01 10:00:05")   # B: 캡처 맨 끝 — 물리적 꼬리
    body = (
        f"printf '{t1}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t1 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{t2}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
    )
    monkeypatch.setattr(wired_ping, "_detect_capture_end", lambda *a, **kw: t2 + 0.2)
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_start="2026-01-01 09:59:00",  # 필터는 활성이지만 아무것도 걸러내지 않음
    )
    assert "error" not in gt
    assert gt["total"] == 1 and gt["ng"] == 0
    assert gt["trailing_dropped"] == 1
    assert any("꼬리" in w for w in gt["warnings"])


# --------------------------------------------------------------------------
# capture_end 기준 물리적 꼬리 판정 (PR #22 3라운드 — Finding A)
# --------------------------------------------------------------------------


def test_capture_end_aware_tail_keeps_real_loss_drops_only_near_end(tmp_path, monkeypatch):
    """capture_end - reply_timeout보다 이전(응답이 올 시간이 충분했던) 무응답은
    진짜 손실로 남고, capture_end에 근접한(응답이 잡힐 기회가 없었을 수 있는)
    무응답만 물리적 꼬리로 제외된다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"   # A: 응답 있음
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '105.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"   # B: 무응답, threshold 밖 → 진짜 손실
        "printf '109.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"   # C: 무응답, threshold 안(끝 근접) → 물리적 꼬리
    )
    # capture_end=110.0, reply_timeout=기본 1.0 → threshold=109.0.
    # B(105.0) <= threshold → 유지(진짜 손실). C(109.5) > threshold → 제외.
    monkeypatch.setattr(wired_ping, "_detect_capture_end", lambda *a, **kw: 110.0)
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 2  # A(ok) + B(ng) — C는 물리적 꼬리로 제외돼 total에서 빠진다
    assert gt["ng"] == 1
    assert gt["ng_epochs"] == [105.0]
    assert gt["trailing_dropped"] == 1
    assert any("꼬리" in w for w in gt["warnings"])


def test_capture_end_unknown_keeps_tail_unanswered_as_loss_with_warning(tmp_path):
    """캡처 끝을 확인하지 못하면 **아무것도 지우지 않는다** — 꼬리 무응답도 손실로
    집계하고 과대 계상 가능성만 경고한다 (PR #22 4라운드). ICMP 마지막 프레임을
    프록시로 쓰던 이전 방식은 임계값을 실제 캡처 끝보다 앞당겨, 마지막 ICMP
    프레임이 진짜 손실이고 pcap이 non-ICMP로 이어지는 캡처에서 그 손실을 조용히
    지웠다. 테스트 환경에선 "x.pcapng"가 실존하지 않아 capinfos가 설치돼 있어도
    항상 실패해 자연히 이 경로를 탄다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 꼬리 무응답
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"  # 꼬리 무응답
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 3 and gt["ng"] == 2      # 꼬리 2건이 손실로 살아남는다
    assert gt["trailing_dropped"] == 0             # 미확인이므로 drop 0건
    assert gt["ng_epochs"] == [101.0, 102.0]
    warn = [w for w in gt["warnings"] if "캡처 끝 시각 미확인" in w]
    assert len(warn) == 1
    assert "2건" in warn[0] and "과대" in warn[0]


def test_capture_end_unknown_without_tail_has_no_warning(tmp_path):
    """캡처 끝 미확인이어도 마지막 응답 이후 무응답이 0건이면 경고하지 않는다 —
    손실률이 과대 계상될 여지 자체가 없다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["trailing_dropped"] == 0
    assert not any("캡처 끝 시각 미확인" in w for w in gt["warnings"])


def test_partial_extraction_warning_reaches_ground_truth(tmp_path, capsys):
    """tshark가 일부 행만 내고 비정상 종료하면(잘린/손상 pcap) 그 경고가 gt warnings로
    올라와야 한다 (PR #22 5라운드). stderr에만 찍으면 웹 업로드 경로는 아무 경고 없이
    '성공한 GT'를 게시해 손실을 조용히 과소 계상한다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "echo 'tshark: The file appears to be damaged' >&2\n"
        "exit 2\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 1
    assert any("일부" in w for w in gt["warnings"])
    assert any("damaged" in w for w in gt["warnings"])
    assert any("낮게 나올 수 있으니" in w for w in gt["warnings"])
    # stderr 출력은 CLI 계약이라 그대로 유지된다(경고가 옮겨간 게 아니라 더해진 것).
    assert "exit 2" in capsys.readouterr().err


def test_detect_capture_end_skips_capinfos_when_cancelled(monkeypatch):
    """취소된 상태면 capinfos를 띄우지 않는다 — 자식 프로세스가 또 하나 늘면 안 된다."""
    calls = []
    monkeypatch.setattr(wired_ping.subprocess, "run",
                        lambda *a, **kw: calls.append(a))
    cancel = threading.Event()
    cancel.set()
    assert wired_ping._detect_capture_end(str(FIXTURE), "tshark", cancel) is None
    assert calls == []


def test_cancel_after_extraction_returns_cancelled_before_capinfos(tmp_path, monkeypatch):
    """추출이 끝난 뒤 취소가 들어오면 capinfos를 호출하기 전에 취소로 끝낸다."""
    calls = []
    monkeypatch.setattr(
        wired_ping, "_detect_capture_end",
        lambda *a, **kw: (calls.append(a), 100.5)[1],
    )
    cancel = threading.Event()

    def _fake_extract(pcap, **kwargs):
        cancel.set()  # 추출 도중 사용자가 취소한 상황
        return [
            (100.0, "10.0.0.1", "10.0.0.2", "8", "7", "1", ""),
            (100.002, "10.0.0.2", "10.0.0.1", "0", "7", "1", ""),
        ]

    monkeypatch.setattr(wired_ping.exping, "extract_icmp_frames", _fake_extract)
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path="tshark", cancel_event=cancel
    )
    assert gt == {"cancelled": True}
    assert calls == []


def test_detect_capture_end_real_capinfos():
    """실제 capinfos 서브프로세스로 성공 경로를 검증한다(PR #22 재리뷰 — 몽키패치로
    가려졌던 라벨("Latest packet time")·플래그(-S 필요) 버그 회귀 방지). capinfos가
    없는 환경(CI 등)에서는 런타임 skip — 스위트 전체 그린은 유지된다."""
    if shutil.which("capinfos") is None:
        pytest.skip("capinfos not installed")
    end = wired_ping._detect_capture_end(str(FIXTURE), shutil.which("tshark") or "tshark")
    assert end == pytest.approx(1700000001.703, abs=0.01)


# --------------------------------------------------------------------------
# 필터 코호트 기준 sender 선정 (PR #22 3라운드 — Finding B)
# --------------------------------------------------------------------------


def test_time_window_selects_cohort_sender_over_background_host(tmp_path):
    """배경 호스트(10.0.0.9)가 전체 캡처에서 최다 요청자여도, time_start 창
    안에는 다른 호스트(10.0.0.1)만 ping했다면 그 창의 sender가 선택되고 그
    흐름이 집계돼야 한다 — 전체 pcap 기준으로 sender를 고르면(구 코드) 배경
    호스트가 잘못 선택된다."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    lines = []
    # 배경 호스트 10.0.0.9 — 창 밖(훨씬 이전 시각)에 요청 5건, 전체 최다
    for i in range(5):
        te = t0 - 100 - i
        lines.append(f"printf '{te}\\t10.0.0.9\\t10.0.0.2\\t8\\t7\\t{100 + i}\\t\\n'")
    # 창 안 — 10.0.0.1이 보낸 요청 2건(응답 있음)만 존재
    lines.append(f"printf '{t0 + 1}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'")
    lines.append(f"printf '{t0 + 1.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'")
    lines.append(f"printf '{t0 + 2}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'")
    lines.append(f"printf '{t0 + 2.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t2\\t\\n'")
    body = "\n".join(lines) + "\n"
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_start="2026-01-01 10:00:00",
    )
    assert "error" not in gt
    assert gt["sender"] == "10.0.0.1"
    assert gt["total"] == 2 and gt["ng"] == 0


def _slow_fake_tshark(tmp_path, sleep_sec: float = 5) -> str:
    """오래 걸리는 가짜 tshark — 취소 전파 검증용.

    `exec`로 sleep에 프로세스를 넘겨 **자식이 하나**가 되게 한다(실제 tshark와 동일).
    exec 없이 sh가 sleep을 자식으로 두면 sh만 죽고 손자 sleep이 stdout 파이프를
    계속 쥐어, 취소가 제대로 전파돼도 부모의 읽기가 sleep 종료까지 EOF를 못 받는다.
    """
    fake = tmp_path / "slow-tshark"
    fake.write_text(f"#!/bin/sh\nexec sleep {sleep_sec}\n")
    fake.chmod(0o755)
    return str(fake)


def test_extract_icmp_frames_cancel_before_start_raises_interrupted(tmp_path):
    """이미 취소된 상태로 들어오면 tshark를 띄우지도 않고 InterruptedError."""
    cancel = threading.Event()
    cancel.set()
    marker = tmp_path / "spawned"
    fake = tmp_path / "marker-tshark"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o755)
    with pytest.raises(InterruptedError):
        exping.extract_icmp_frames("x.pcapng", tshark=str(fake), cancel_event=cancel)
    assert not marker.exists()


def test_extract_icmp_frames_cancel_kills_running_tshark(tmp_path):
    """실행 중 취소되면 자식 tshark를 즉시 종료하고 InterruptedError를 낸다 —
    무선 추출(extractor._cancel_watcher)과 같은 계약. 취소를 무시하면 자식이
    child_timeout(기본 3600초)까지 살아 임시파일과 pcap 핸들을 계속 쥔다."""
    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.daemon = True
    timer.start()
    t0 = time.monotonic()
    with pytest.raises(InterruptedError):
        exping.extract_icmp_frames(
            "x.pcapng", tshark=_slow_fake_tshark(tmp_path), cancel_event=cancel
        )
    timer.cancel()
    assert time.monotonic() - t0 < 3  # sleep 5초가 끝나기를 기다리지 않았다


def test_extract_icmp_frames_without_cancel_event_unchanged(tmp_path):
    """cancel_event 미전달(기본 None) 경로는 동작 불변 — 기존 호출부 회귀 방지."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    frames = exping.extract_icmp_frames("x.pcapng", tshark=_fake_tshark(tmp_path, body))
    assert len(frames) == 2 and frames[0][0] == pytest.approx(100.0)


def test_build_ground_truth_cancelled_returns_cancelled_dict(tmp_path):
    """취소되면 error가 아니라 {"cancelled": True} — 파이프라인이 전체 분석 취소와
    같은 방식으로 처리한다(사용자에게 실패가 아니라 취소로 보여야 한다)."""
    cancel = threading.Event()
    cancel.set()
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_slow_fake_tshark(tmp_path), cancel_event=cancel
    )
    assert gt == {"cancelled": True}


def test_ip_filter_selects_cohort_sender_among_multiple_hosts(tmp_path):
    """같은 시간대에 두 호스트가 함께 ping해도, ip_filter로 지정한 호스트의
    요청 수가 더 적더라도 sender로 선택된다(ip_filter의 sender 지정 효과)."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        # 10.0.0.9 — 요청 3건(더 많음, ip_filter 없으면 이쪽이 sender로 뽑힌다)
        f"printf '{t0}\\t10.0.0.9\\t10.0.0.2\\t8\\t7\\t101\\t\\n'\n"
        f"printf '{t0 + 0.1}\\t10.0.0.9\\t10.0.0.2\\t8\\t7\\t102\\t\\n'\n"
        f"printf '{t0 + 0.2}\\t10.0.0.9\\t10.0.0.2\\t8\\t7\\t103\\t\\n'\n"
        # 10.0.0.1 — 요청 1건(응답 있음, 더 적음)
        f"printf '{t0 + 0.3}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.302}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.1",
    )
    assert "error" not in gt
    assert gt["sender"] == "10.0.0.1"
    assert gt["total"] == 1 and gt["ng"] == 0


# --------------------------------------------------------------------------
# capinfos 이식성·취소 응답성, 미확인 캡처 끝 경고 정밀화 (PR #22 10라운드)
# --------------------------------------------------------------------------


def _fake_capinfos(tmp_path, name: str, body: str) -> str:
    """tshark 형제 경로에 놓는 가짜 capinfos. tshark 실행파일도 함께 만든다."""
    (tmp_path / name).write_text("#!/bin/sh\n" + body)
    (tmp_path / name).chmod(0o755)
    return str(tmp_path / name)


def test_capinfos_sibling_uses_tshark_suffix(tmp_path):
    """Windows에서는 tshark.exe 옆에 capinfos.exe가 있다 — 접미사 없는 이름만 보면
    형제 탐색이 항상 실패해 캡처 끝 미확인 경로로 떨어진다 (PR #22 10라운드)."""
    tshark = tmp_path / "tshark.exe"
    tshark.write_text("#!/bin/sh\n:\n")
    tshark.chmod(0o755)
    _fake_capinfos(tmp_path, "capinfos.exe",
                   "printf 'Latest packet time:   1700000001.703000\\n'\n")
    end = wired_ping._detect_capture_end("x.pcapng", str(tshark))
    assert end == pytest.approx(1700000001.703, abs=0.01)


def test_detect_capture_end_cancel_during_capinfos(tmp_path):
    """capinfos 실행 **중** 취소가 들어와도 즉시 끊어야 한다 — subprocess.run은
    timeout(30초)까지 블록돼 /api/cancel이 성공을 보고한 뒤에도 자식이 남는다."""
    tshark = tmp_path / "tshark"
    tshark.write_text("#!/bin/sh\n:\n")
    tshark.chmod(0o755)
    _fake_capinfos(tmp_path, "capinfos", "exec sleep 5\n")
    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.daemon = True
    timer.start()
    t0 = time.monotonic()
    assert wired_ping._detect_capture_end("x.pcapng", str(tshark), cancel) is None
    timer.cancel()
    assert time.monotonic() - t0 < 3  # sleep 5초를 기다리지 않았다


def test_unverified_warning_counts_rotating_target_unanswered(tmp_path):
    """회전 다중 target ping에서 무응답 A 뒤에 응답된 B가 오면 A는 '연속 꼬리'가
    아니어서 경고에서 빠졌다 — 그러나 A의 응답 창이 캡처 끝에 잘렸을 수 있다.
    경고 대상은 '마지막 관측 프레임까지 응답 기회가 검증되지 않은 무응답'이다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"    # A: 무응답
        "printf '100.1\\t10.0.0.1\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"    # B: 응답 있음
        "printf '100.102\\t10.0.0.3\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 2 and gt["ng"] == 1
    assert gt["trailing_dropped"] == 0
    warn = [w for w in gt["warnings"] if "캡처 끝 시각 미확인" in w]
    assert len(warn) == 1 and "1건" in warn[0]


def test_unverified_warning_skips_unanswered_closed_inside_capture(tmp_path):
    """응답 창이 캡처 안에서 닫힌 무응답(마지막 프레임보다 reply_timeout 이상 앞선
    요청)은 확정 손실이므로 경고 대상이 아니다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"    # A: 무응답, 창이 닫힘
        "printf '102.0\\t10.0.0.1\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"    # B: 응답 있음
        "printf '102.002\\t10.0.0.3\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["ng"] == 1
    assert not any("캡처 끝 시각 미확인" in w for w in gt["warnings"])


# --------------------------------------------------------------------------
# 이중 필터 AND·capinfos 취소 전파 (PR #22 11라운드)
# --------------------------------------------------------------------------


def test_ip_filter_and_derived_filter_combine_as_and_direct_topology(tmp_path):
    """직접 토폴로지(mac_filter 대상 STA == sender)에서 derived_ip_filter는 sender
    자신의 IP다 — 이를 사용자 ip_filter(target1 지정)와 '대체'가 아니라 '병행(AND)'로
    적용해야 사용자가 명시한 target 좁히기가 살아남는다 (PR #22 11라운드 — Finding A
    ①). 10라운드 방식(대체)이었다면 유도값이 sender 자신의 IP라 '_filter_exchanges의
    sender 포함 → 전체 유지' 경로를 타 narrowing이 사라져 total==2가 됐을 것이다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"
        "printf '101.002\\t10.0.0.3\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.2",       # 사용자: target1만
        derived_ip_filter="10.0.0.1",  # mac_filter 유도값: sender 자신의 IP
    )
    assert "error" not in gt
    assert gt["sender"] == "10.0.0.1"
    assert gt["total"] == 1
    assert set(gt["targets"]) == {"10.0.0.2"}


def test_ip_filter_and_derived_filter_combine_as_and_upstream_topology(tmp_path):
    """상류 토폴로지에서 사용자가 sender 자신의 IP를 ip_filter로 줘도(narrowing
    의도가 아님), derived_ip_filter(mac_filter로 유도된 대상 STA IP)는 여전히
    target을 좁혀야 한다 — 10라운드에서 확립한 동작이 병행(AND) 구조에서도 유지됨을
    확인 (PR #22 11라운드 — Finding A ②)."""
    body = (
        "printf '100.0\\t10.0.0.9\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.9\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.9\\t10.0.0.3\\t8\\t7\\t2\\t\\n'\n"
        "printf '101.002\\t10.0.0.3\\t10.0.0.9\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        ip_filter="10.0.0.9",        # 사용자: sender 자신 (narrowing 의도 아님)
        derived_ip_filter="10.0.0.2",  # mac_filter 유도값: 대상 STA IP
    )
    assert "error" not in gt
    assert gt["sender"] == "10.0.0.9"
    assert set(gt["targets"]) == {"10.0.0.2"}


def test_cancel_during_capinfos_returns_cancelled_not_unknown_capture_end(tmp_path):
    """capinfos 실행 도중 취소되면 _detect_capture_end가 None을 반환하는데, 이를
    다른 실패 사유와 구분 없이 '캡처 끝 미확인'으로 처리하면 취소를 무시한 채
    (경고만 붙여) 부분 결과가 정상 GT로 게시된다 — 취소는 {"cancelled": True}로
    보고해야 한다 (PR #22 11라운드 — Finding B)."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    tshark = _fake_tshark(tmp_path, body)
    _fake_capinfos(tmp_path, "capinfos", "exec sleep 5\n")
    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.daemon = True
    timer.start()
    t0 = time.monotonic()
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=tshark, cancel_event=cancel)
    timer.cancel()
    assert gt == {"cancelled": True}
    assert time.monotonic() - t0 < 3  # sleep 5초를 기다리지 않았다


# --------------------------------------------------------------------------
# time_end 경계 요청 일관 제외 (PR #22 13라운드 — Codex P2)
# --------------------------------------------------------------------------


def test_time_end_boundary_request_excluded_when_reply_window_crosses(tmp_path):
    """time_end가 요청과 응답 사이에 떨어지면: 유선은 전체 캡처 pairing이라
    answered로 잡히지만, 무선 extract_frames는 `frame.time < time_end`로 응답
    프레임을 이미 제거해 그 요청을 관측하지 못한다 — GT가 이를 그대로 answered로
    total에 포함시키면 무선과 다른 모집단을 비교하게 돼 인위적 초과 무선 손실이
    '모니터 누락'으로 오귀속된다. _drop_unreachable_tail(capture_end 기준)과
    같은 원리를 time_end 경계에도 적용해 응답 창이 경계를 넘는 요청은 일관되게
    제외해야 한다(수정 전 RED: total에 포함됨)."""
    end_epoch = _local_epoch("2026-01-01 10:00:10")
    a_req = end_epoch - 0.5    # 응답 창(기본 ±1.0s)이 end_epoch를 넘는다 → 제외 대상
    a_rep = end_epoch + 0.2    # 응답이 경계 뒤에 있음(무선은 못 봄)
    b_req = end_epoch - 3.0    # 응답 창이 경계 안에서 완전히 닫힌다 → 정상 포함
    b_rep = b_req + 0.002
    body = (
        f"printf '{a_req}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{a_rep}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{b_req}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        f"printf '{b_rep}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:00:10",
    )
    assert "error" not in gt
    assert gt["total"] == 1 and gt["ng"] == 0    # A는 제외, B만 남는다
    warn = [w for w in gt["warnings"] if "구간 끝 경계 요청" in w]
    assert len(warn) == 1 and "1건" in warn[0]


def test_time_end_boundary_request_kept_when_reply_arrives_before_boundary(tmp_path):
    """응답 창(±reply_timeout)이 time_end 임계값에 걸리더라도, 실제 응답이 그보다
    훨씬 일찍(time_end 이전에) 도착했다면 제외하면 안 된다 — Exchange는 응답
    epoch을 별도로 저장하지 않지만 `x.time + x.rtt`가 곧 응답 epoch이라 정확한
    판정이 가능하다(PR #22 13라운드 보강 — team-lead 정정). 무선도 그 응답
    프레임을 보므로(frame.time < time_end) 양쪽 다 matched — 여기서 배제하면
    무선(matched)과 GT(미포함) 사이에 반대 방향 불일치가 새로 생긴다(수정 전
    RED: 응답 시각을 안 보고 요청 시각만으로 무조건 배제해 필터 구간이 비어
    error가 남)."""
    end_epoch = _local_epoch("2026-01-01 10:00:10")
    req = end_epoch - 0.5   # 응답 창(±1.0s)이 임계값을 넘지만
    rep = req + 0.1          # 응답은 훨씬 일찍(경계보다 한참 전) 도착
    body = (
        f"printf '{req}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{rep}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:00:10",
    )
    assert "error" not in gt
    assert gt["total"] == 1 and gt["ng"] == 0
    assert not any("구간 끝 경계 요청" in w for w in gt["warnings"])


def test_timeout_before_time_end_kept_when_late_reply_is_after_boundary(tmp_path):
    """응답 제한시간이 구간 안에서 이미 끝난 요청은 late reply가 time_end 뒤에
    관측돼도 Timeout/NG 모집단에 남는다."""
    end_epoch = _local_epoch("2026-01-01 10:00:10")
    req = end_epoch - 2.0
    late_rep = end_epoch + 0.2
    body = (
        f"printf '{req}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{late_rep}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:00:10", reply_timeout=1.0,
    )
    assert "error" not in gt
    assert gt["total"] == 1
    assert gt["ng"] == 1
    assert gt["late_count"] == 1
    assert not any("구간 끝 경계 요청" in w for w in gt["warnings"])


def test_time_end_boundary_keeps_requests_whose_reply_window_closes_inside(tmp_path):
    """응답 창이 경계에서 충분히 멀어 안에서 완전히 닫히는 요청은 정상 포함된다 —
    과잉 배제 방지."""
    end_epoch = _local_epoch("2026-01-01 10:00:10")
    req = end_epoch - 5.0
    rep = req + 0.002
    body = (
        f"printf '{req}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{rep}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:00:10",
    )
    assert "error" not in gt
    assert gt["total"] == 1 and gt["ng"] == 0
    assert not any("구간 끝 경계 요청" in w for w in gt["warnings"])


def test_time_end_boundary_exclusion_inactive_without_time_end(tmp_path):
    """time_end가 없으면 경계 배제 로직 자체가 발동하지 않는다 — 응답이
    reply_timeout 안에서 아무리 늦게 와도 정상 answered로 집계된다."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    req = t0
    rep = t0 + 0.9  # 기본 reply_timeout(1.0s) 안이지만 여유가 적다
    body = (
        f"printf '{req}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{rep}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 1 and gt["ng"] == 0
    assert not any("구간 끝 경계 요청" in w for w in gt["warnings"])


# --------------------------------------------------------------------------
# 경계 컷오프 무선 미러링 (PR #22 14라운드 — Finding B)
# --------------------------------------------------------------------------


def test_boundary_cutoff_epoch_exposed_when_time_end_active(tmp_path):
    """time_end가 활성이면 gt에 boundary_cutoff_epoch(= end_epoch - reply_timeout)를
    노출한다 — charts.js가 유선의 경계 배제 술어를 무선 비교(senderItems)에도
    미러링할 수 있도록. 13라운드는 유선 GT만 배제해 무선 full_list에는 그
    요청이 여전히 loss로 남는 비대칭이 있었다(수정 전 RED: 키 자체가 없음)."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        f"printf '{t0}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_end="2026-01-01 10:00:10",
    )
    assert "error" not in gt
    end_epoch = _local_epoch("2026-01-01 10:00:10")
    assert gt["boundary_cutoff_epoch"] == pytest.approx(end_epoch - 1.0)


def test_boundary_cutoff_epoch_absent_without_time_end(tmp_path):
    """time_end가 없으면 boundary_cutoff_epoch 키 자체를 만들지 않는다 —
    charts.js가 `typeof gt.boundary_cutoff_epoch === 'number'`로 미러링 여부를
    판정하므로, 키 부재가 곧 '미러링 비활성'이어야 한다."""
    t0 = _local_epoch("2026-01-01 10:00:00")
    body = (
        f"printf '{t0}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t0 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert "boundary_cutoff_epoch" not in gt


# --------------------------------------------------------------------------
# RTT 통계 및 exchange 노출 (Task 1)
# --------------------------------------------------------------------------


def test_rtt_stats_p95_boundaries():
    """p95 = 정렬 후 ceil(0.95*n)-1 인덱스 (nearest-rank)."""
    one = wired_ping._rtt_stats([Exchange(1.0, "t", 0.005)])
    assert one == {"n": 1, "min_ms": 5.0, "avg_ms": 5.0, "max_ms": 5.0, "p95_ms": 5.0}

    xs = [Exchange(float(i), "t", (i + 1) / 1000) for i in range(20)]  # 1..20ms
    st = wired_ping._rtt_stats(xs)
    assert st["n"] == 20
    assert st["min_ms"] == 1.0 and st["max_ms"] == 20.0 and st["avg_ms"] == 10.5
    assert st["p95_ms"] == 19.0  # ceil(0.95*20)-1 = idx 18 → 19ms


def test_rtt_stats_none_when_no_answers():
    """정직한 공백 — 응답이 하나도 없으면 통계 대신 None."""
    assert wired_ping._rtt_stats([]) is None
    assert wired_ping._rtt_stats([Exchange(1.0, "t", None)]) is None


def test_exchanges_and_rtt_stats_exposed(tmp_path):
    """GT dict에 exchange별 RTT가 노출되고 손실 집계와 모집단이 일치한다."""
    # 기존 test_counts_ok_ng_and_loss_pct와 동일한 body 픽스처를 그대로 재사용한다.
    body = _BODY_OK
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))

    assert len(gt["exchanges"]) == gt["total"]
    answered = [e for e in gt["exchanges"] if e["rtt_ms"] is not None]
    assert len(answered) == gt["ok"]
    assert all(e["rtt_ms"] > 0 for e in answered)
    assert all(
        set(e) == {"epoch", "target", "rtt_ms", "late_rtt_ms"}
        for e in gt["exchanges"]
    )

    rs = gt["rtt_stats"]
    assert rs["n"] == gt["ok"]
    assert rs["min_ms"] <= rs["avg_ms"] <= rs["max_ms"]
    assert rs["min_ms"] <= rs["p95_ms"] <= rs["max_ms"]


def test_all_unanswered_omits_rtt_stats(tmp_path, monkeypatch):
    """전부 무응답이면 rtt_stats 키 자체가 없다 — capture_end 밖의 픽스처."""
    # 응답이 전혀 없으면서 error가 발생하지 않는 경우: capture_end를
    # 충분히 뒤에 둬서 all pending으로 인정하되, 일단 요청-응답 시간 내에
    # 응답이 도착하지 않은 경우.
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.1\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        "printf '100.2\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
    )
    # capture_end=102.0 → threshold=101.0 → 세 요청이 모두 threshold 전에
    # 있으므로 유효하지만 응답이 도착하지 않음
    monkeypatch.setattr(wired_ping, "_detect_capture_end", lambda *a, **kw: 102.0)
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 3 and gt["ng"] == 3 and gt["ok"] == 0
    assert "rtt_stats" not in gt
    assert len(gt["exchanges"]) == 3
    assert all(e["rtt_ms"] is None for e in gt["exchanges"])


class TestWarningsOutContract:
    """`extraction_partial`이 의존하는 계약을 **동작으로** 고정한다.

    `exping.extract_icmp_frames`의 `warnings_out`에는 **부분 실패 경고만** 담긴다.
    정보성 경고를 거기 추가하면 멀쩡한 유선 GT가 `extraction_partial=True`로
    표시돼 판정에서 조용히 빠진다 — 이 PR이 막으려는 문제(관측 한계를 사실로
    오인)와 같은 종류의 오류를 반대 방향으로 만드는 셈이다.
    """

    def test_clean_extraction_is_not_partial(self, tmp_path):
        gt = wired_ping.build_ground_truth(
            "x.pcapng", tshark_path=_fake_tshark(tmp_path, _BODY_OK))
        assert "error" not in gt
        assert gt["extraction_partial"] is False
        # 이후 단계의 경고(꼬리 배제 등)가 있어도 플래그는 영향받지 않는다.
        assert gt["total"] == 3

    def test_abnormal_exit_after_rows_is_partial(self, tmp_path):
        """행을 일부 뱉고 비정상 종료 — 손실률이 과소 계상되므로 판정 불가."""
        body = _BODY_OK + "exit 2\n"
        gt = wired_ping.build_ground_truth(
            "x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
        assert "error" not in gt, "프레임은 건졌으므로 error가 아니다"
        assert gt["extraction_partial"] is True
        assert any("exit 2" in w for w in gt["warnings"])

    def test_partial_gt_is_rejected_for_judgment(self, tmp_path):
        """플래그가 실제로 판정에서 걸러지는지 — 두 모듈의 계약이 이어지는지 확인."""
        from analyzer.web.structured import _loss_for_judgment

        gt = wired_ping.build_ground_truth(
            "x.pcapng", tshark_path=_fake_tshark(tmp_path, _BODY_OK + "exit 2\n"))
        used, basis = _loss_for_judgment({"ground_truth": gt}, 7.5, True)
        assert basis == "wireless_observed" and used == 7.5

    def test_clean_gt_is_used_for_judgment(self, tmp_path):
        from analyzer.web.structured import _loss_for_judgment

        gt = wired_ping.build_ground_truth(
            "x.pcapng", tshark_path=_fake_tshark(tmp_path, _BODY_OK))
        used, basis = _loss_for_judgment({"ground_truth": gt}, 7.5, True)
        assert basis == "wired_gt" and used == gt["loss_pct"]
