"""wired_ping.build_ground_truth — 유선 pcap ping ground truth 빌더."""
import pytest

from analyzer.core import wired_ping


def _fake_tshark(tmp_path, body: str) -> str:
    """TSV를 뱉는 가짜 tshark 실행파일 (tests/test_exping.py 패턴)."""
    fake = tmp_path / "fake-tshark"
    fake.write_text("#!/bin/sh\n" + body)
    fake.chmod(0o755)
    return str(fake)


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
