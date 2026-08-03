"""wired_ping.build_ground_truth — 유선 pcap ping ground truth 빌더."""
import datetime as dt
import shutil
from pathlib import Path

import pytest

from analyzer.core import wired_ping

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


def test_capinfos_absent_falls_back_to_icmp_max_epoch_with_warning(tmp_path):
    """capinfos가 없거나(또는 대상 pcap을 못 읽으면) ICMP 마지막 프레임 epoch을
    캡처 끝 프록시로 쓰고 경고를 남긴다. 테스트 환경에선 "x.pcapng"가 실제
    파일이 아니라 capinfos가 설치돼 있어도 항상 실패해 자연히 이 경로를 탄다."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert any("capinfos" in w for w in gt["warnings"])


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
