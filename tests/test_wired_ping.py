"""wired_ping.build_ground_truth — 유선 pcap ping ground truth 빌더."""
import datetime as dt

import pytest

from analyzer.core import wired_ping


def _fake_tshark(tmp_path, body: str) -> str:
    """TSV를 뱉는 가짜 tshark 실행파일 (tests/test_exping.py 패턴)."""
    fake = tmp_path / "fake-tshark"
    fake.write_text("#!/bin/sh\n" + body)
    fake.chmod(0o755)
    return str(fake)


def _local_epoch(s: str) -> float:
    """테스트 전용 — build_ground_truth._parse_local_epoch와 동일 규칙(로컬 tz)."""
    return dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()


def test_counts_ok_ng_and_loss_pct(tmp_path):
    """요청 3건 중 가운데 1건 무응답 → total 3 / ok 2 / ng 1 / 33.33%."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 무응답
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
        "printf '102.003\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t3\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 3 and gt["ok"] == 2 and gt["ng"] == 1
    assert gt["loss_pct"] == pytest.approx(33.33)
    assert gt["sender"] == "10.0.0.1"
    assert gt["targets"] == {"10.0.0.2": {"total": 3, "ng": 1}}
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


def test_trailing_unanswered_dropped_with_warning(tmp_path):
    """캡처가 응답보다 먼저 끊긴 꼬리 무응답은 NG로 세지 않는다 (EXPING 규칙)."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 꼬리 무응답
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert gt["total"] == 1 and gt["ng"] == 0
    assert gt["trailing_dropped"] == 1
    assert any("꼬리" in w for w in gt["warnings"])


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


def test_all_requests_unanswered_100_loss(tmp_path):
    """요청 3건 전부 무응답 (100% 손실) → 정확한 에러 메시지 (drop 이후 구분)."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
    )
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


def test_ip_filter_keeps_only_matching_target(tmp_path):
    """ip_filter에 sender가 없으면 target(dst) 매칭 exchange만 남는다."""
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
    assert gt["total"] == 1
    assert gt["targets"] == {"10.0.0.3": {"total": 1, "ng": 0}}


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


def test_physical_trailing_still_dropped_with_filter_active(tmp_path):
    """필터가 활성이어도 캡처 전체의 진짜(물리적) 꼬리 무응답은 여전히 제외된다."""
    t1 = _local_epoch("2026-01-01 10:00:00")   # A: 응답 있음
    t2 = _local_epoch("2026-01-01 10:00:05")   # B: 캡처 맨 끝 — 물리적 꼬리
    body = (
        f"printf '{t1}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        f"printf '{t1 + 0.002}\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        f"printf '{t2}\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth(
        "x.pcapng", tshark_path=_fake_tshark(tmp_path, body),
        time_start="2026-01-01 09:59:00",  # 필터는 활성이지만 아무것도 걸러내지 않음
    )
    assert "error" not in gt
    assert gt["total"] == 1 and gt["ng"] == 0
    assert gt["trailing_dropped"] == 1
    assert any("꼬리" in w for w in gt["warnings"])
