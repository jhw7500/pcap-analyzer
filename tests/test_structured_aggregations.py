"""structured.py 초당 집계 함수 단위 테스트 (_retry_per_sec, _ping_per_sec).

PR #9 리뷰에서 지적된 경계 케이스를 고정한다:
- 빈 입력
- loss만 있는 초 → avg_rtt 는 None (0/NaN 아님)
- matched 중 rtt_ms 없는 게 있어도 평균이 왜곡되지 않음 (rtt_count 분모)
- matched/loss/loss_gap 외 status 무시
- dst_mac 없는 ping도 IP↔장치 학습으로 STA 식별
"""
from analyzer.web.structured import _ping_per_sec, _retry_per_sec


class _Frame:
    def __init__(self, epoch, retry):
        self.epoch = epoch
        self.retry = retry


def test_retry_per_sec_empty():
    assert _retry_per_sec([]) == []


def test_retry_per_sec_basic():
    out = _retry_per_sec([_Frame(100.1, True), _Frame(100.5, False), _Frame(101.2, True)])
    assert out == [
        {"epoch": 100, "retry": 1, "total": 2, "retry_pct": 50.0},
        {"epoch": 101, "retry": 1, "total": 1, "retry_pct": 100.0},
    ]


def _ping(epoch, status, rtt=None, *, src="10", dst="20",
          src_mac="AP1(bb)", dst_mac="STA1(aa)"):
    return {
        "epoch": epoch, "status": status, "rtt_ms": rtt,
        "src": src, "dst": dst, "src_mac": src_mac, "dst_mac": dst_mac,
    }


def test_ping_per_sec_empty():
    assert _ping_per_sec([]) == []


def test_ping_per_sec_loss_only_avg_rtt_none():
    out = _ping_per_sec([_ping(100.1, "loss"), _ping(100.5, "loss_gap")])
    assert out[0]["avg_rtt"] is None
    assert out[0]["loss"] == 2 and out[0]["matched"] == 0
    assert out[0]["loss_pct"] == 100.0


def test_ping_per_sec_avg_rtt_uses_rtt_count_not_matched():
    # matched 3개 중 rtt 2개만 → avg = (2+4)/2 = 3.0 (matched 3으로 나누면 안 됨)
    full = [
        _ping(100.1, "matched", 2.0),
        _ping(100.2, "matched", 4.0),
        _ping(100.3, "matched", None),
    ]
    out = _ping_per_sec(full)
    assert out[0]["avg_rtt"] == 3.0
    assert out[0]["matched"] == 3


def test_ping_per_sec_unknown_status_ignored():
    out = _ping_per_sec([_ping(100.1, "observed"), _ping(100.2, "matched", 1.0)])
    assert out[0]["total"] == 1 and out[0]["matched"] == 1


def test_ping_per_sec_ip_identifies_sta_without_mac():
    full = [
        # 매핑 학습: dst IP 20 → STA1
        _ping(100.1, "matched", 1.0, src="10", dst="20",
              src_mac="AP1(bb)", dst_mac="STA1(aa)"),
        # MAC 비어도 src IP 20(STA1) 으로 식별
        _ping(100.2, "loss", None, src="20", dst="10",
              src_mac="", dst_mac=""),
    ]
    out = _ping_per_sec(full)
    by = out[0]["by_dev"]
    assert "STA1(aa)" in by
    assert by["STA1(aa)"]["loss"] == 1 and by["STA1(aa)"]["matched"] == 1
    assert "?" not in by  # 미매핑 fallback 없이 STA로 귀속
