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


def test_retry_per_sec_skips_none_epoch():
    # epoch 없는 프레임은 건너뛰고 build를 깨지 않는다.
    out = _retry_per_sec([_Frame(None, True), _Frame(100.1, False)])
    assert out == [{"epoch": 100, "retry": 0, "total": 1, "retry_pct": 0.0}]


def test_ping_per_sec_ip_fallback_key_when_no_sta():
    # 어떤 항목도 STA로 매핑 안 되면 by_dev 키가 IP(또는 '?') — 장치명이 아님.
    full = [_ping(100.1, "loss", None, src="192.168.0.99", dst="192.168.0.1",
                  src_mac="", dst_mac="")]
    out = _ping_per_sec(full)
    by = out[0]["by_dev"]
    assert all(not k.startswith("STA") for k in by)  # STA 장치명 키 없음
    assert out[0]["loss"] == 1  # 전체 집계 agg 에는 포함


# ── _device_entry_stats 10초 버킷 (단일 패스 재작성 회귀 고정) ──────────────
# 구현이 버킷마다 전체 프레임을 재스캔하던 O(span/10 × frames)에서 프레임당
# 버킷 인덱스를 한 번 계산하는 단일 패스로 바뀌었다(2시간·143만 프레임 실측
# 315초 → 단일 패스). 출력이 이전과 완전히 동일해야 하므로 값을 통째로 고정한다.
from analyzer.core.models import Frame  # noqa: E402
from analyzer.web.structured import (  # noqa: E402
    _bucket_rssi_timeline,
    _device_entry_stats,
)


def _f(number, epoch, *, ta="", ra="", retry=False, subtype="40",
       mcs="", mcs_phy="", data_rate="", rssi=""):
    return Frame(
        number=number, epoch=epoch, timestamp="", retry=retry, subtype=subtype,
        protocol="", length=100, mcs=mcs, rssi=rssi, ta=ta, ra=ra,
        ip_src="", ip_dst="", icmp_type="", arp_opcode="", tcp_len="",
        tcp_flags="", seq="", mcs_phy=mcs_phy, data_rate=data_rate,
    )


def test_device_bucket_stats_exact_values_with_empty_gap():
    frames = [
        _f(1, 1000.0, ta="aa", mcs="7", mcs_phy="HT"),
        _f(2, 1005.0, ta="aa", retry=True, mcs="7", mcs_phy="HT"),
        _f(3, 1009.9, ta="bb", ra="aa"),          # 수신 — tx 아님
        # 1010~1019 구간은 프레임 없음 → 빈 버킷이 그대로 출력돼야 한다
        _f(4, 1021.0, ta="aa", data_rate="6", mcs_phy="Legacy"),
    ]
    entry = _device_entry_stats(frames, lambda f: f.ta == "aa", "aa", "STA")

    assert entry["per_bucket"] == [
        {
            "epoch": 1000, "total": 3, "retry": 1, "retry_pct": 33.3,
            "mcs_breakdown": "HT MCS7×2", "avg_mcs": 7.0, "legacy_pct": 0,
            "tx_total": 2, "phy_mode_dist": {"HT": 2},
        },
        {
            "epoch": 1010, "total": 0, "retry": 0, "retry_pct": 0,
            "mcs_breakdown": "", "avg_mcs": None, "legacy_pct": 0,
            "tx_total": 0, "phy_mode_dist": {},
        },
        {
            "epoch": 1020, "total": 1, "retry": 0, "retry_pct": 0.0,
            "mcs_breakdown": "Legacy 6Mbps×1", "avg_mcs": None,
            "legacy_pct": 100.0, "tx_total": 1, "phy_mode_dist": {"Legacy": 1},
        },
    ]


def test_device_bucket_boundary_frame_goes_to_next_bucket():
    # 정확히 경계(1010.0)인 프레임은 구 비교식 `start <= epoch < end`와 동일하게
    # 다음 버킷에 들어가야 한다.
    frames = [_f(1, 1000.0, ta="aa"), _f(2, 1010.0, ta="aa")]
    entry = _device_entry_stats(frames, lambda f: f.ta == "aa", "aa", "STA")
    assert [b["epoch"] for b in entry["per_bucket"]] == [1000, 1010]
    assert [b["total"] for b in entry["per_bucket"]] == [1, 1]


def test_device_bucket_stats_skips_corrupt_epochs():
    frames = [
        _f(1, 1000.0, ta="aa"),
        _f(2, float("nan"), ta="aa"),
        _f(3, float("inf"), ta="aa"),
    ]
    entry = _device_entry_stats(frames, lambda f: f.ta == "aa", "aa", "STA")
    assert entry["per_bucket"] == [
        {
            "epoch": 1000, "total": 1, "retry": 0, "retry_pct": 0.0,
            "mcs_breakdown": "", "avg_mcs": None, "legacy_pct": 0,
            "tx_total": 1, "phy_mode_dist": {},
        },
    ]


# ── _bucket_rssi_timeline (RSSI 1초 버킷 집계) ─────────────────────────────
def test_bucket_rssi_timeline_aggregates_per_second():
    frames = [
        _f(1, 1000.0, ta="aa", rssi="-50", mcs="7"),
        _f(2, 1000.4, ta="aa", rssi="-60", mcs="7"),
        _f(3, 1000.9, ta="aa", rssi="-70", mcs="3"),
        _f(4, 1001.2, ta="aa", rssi="-40", mcs="9"),
    ]
    out = _bucket_rssi_timeline(frames)
    assert out == [
        {"epoch": 1000, "rssi": -60.0, "rssi_min": -70, "rssi_max": -50,
         "n": 3, "mcs": 7},
        {"epoch": 1001, "rssi": -40.0, "rssi_min": -40, "rssi_max": -40,
         "n": 1, "mcs": 9},
    ]


def test_bucket_rssi_timeline_skips_corrupt_epoch_and_missing_rssi():
    frames = [
        _f(1, float("nan"), ta="aa", rssi="-50"),
        _f(2, 1000.0, ta="aa", rssi=""),      # rssi_first None
        _f(3, 1000.5, ta="aa", rssi="-55"),
    ]
    out = _bucket_rssi_timeline(frames)
    assert out == [
        {"epoch": 1000, "rssi": -55.0, "rssi_min": -55, "rssi_max": -55,
         "n": 1, "mcs": None},
    ]


def test_bucket_rssi_timeline_empty():
    assert _bucket_rssi_timeline([]) == []
