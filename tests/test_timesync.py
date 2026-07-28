"""analyzer.core.timesync 단위 테스트."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from analyzer.core import timesync as ts

KST = timezone(timedelta(hours=9))


# --------------------------------------------------------------------------
# NTP 타임스탬프 파싱
# --------------------------------------------------------------------------


def test_parse_ntp_timestamp_nanoseconds():
    """tshark 는 ns 9자리를 내보내는데 %f 는 6자리까지만 받는다."""
    got = ts.parse_ntp_timestamp("Jul 21, 2026 05:57:35.004315599 UTC")
    want = datetime(2026, 7, 21, 5, 57, 35, 4315, tzinfo=timezone.utc).timestamp()
    assert got == pytest.approx(want, abs=1e-6)


def test_parse_ntp_timestamp_rejects_unset():
    assert ts.parse_ntp_timestamp("NULL") is None
    assert ts.parse_ntp_timestamp("") is None
    # NTP 미설정 필드는 1900-01-01 로 렌더링된다 — epoch 음수라 걸러야 한다.
    assert ts.parse_ntp_timestamp("Jan  1, 1900 00:00:00.000000000 UTC") is None


def test_parse_ntp_timestamp_without_fraction():
    got = ts.parse_ntp_timestamp("Jul 21, 2026 05:57:35 UTC")
    want = datetime(2026, 7, 21, 5, 57, 35, tzinfo=timezone.utc).timestamp()
    assert got == pytest.approx(want, abs=1e-6)


def test_parse_ntp_tsv_skips_rows_with_unset_fields():
    tsv = (
        "1137\t1753077430.683942\tJul 21, 2026 05:57:35.000233528 UTC\t"
        "Jul 21, 2026 05:57:35.004315599 UTC\t192.168.0.10\n"
        "1138\t1753077431.0\tNULL\tJul 21, 2026 05:57:36.000000000 UTC\t192.168.0.10\n"
        "\n"
    )
    rows = ts.parse_ntp_tsv(tsv)
    assert len(rows) == 1
    assert rows[0].frame_no == 1137
    assert rows[0].src == "192.168.0.10"


def test_resolve_tz_iana_and_fixed_offset():
    assert ts.resolve_tz(None) is None
    assert ts.resolve_tz("") is None
    assert ts.resolve_tz("+09:00").utcoffset(None) == timedelta(hours=9)
    assert ts.resolve_tz("+0900").utcoffset(None) == timedelta(hours=9)
    assert ts.resolve_tz("-05:30").utcoffset(None) == timedelta(hours=-5, minutes=-30)
    seoul = ts.resolve_tz("Asia/Seoul")
    assert seoul.utcoffset(datetime(2026, 7, 21)) == timedelta(hours=9)


def test_resolve_tz_rejects_garbage():
    with pytest.raises(ValueError, match="타임존"):
        ts.resolve_tz("Mars/Olympus")


def test_parse_sync_events_honours_explicit_tz(tmp_path):
    """회귀: 분석 머신 TZ 가 다르면 매칭이 통째로 0건이 되던 문제."""
    p = tmp_path / "sys.log"
    p.write_text(
        "2026-07-21 14:57:02.388 systemd-timesyncd[info] Contacted time server 192.168.0.10:123.\n",
        encoding="utf-8",
    )
    kst = ts.parse_sync_events(p, tz=ts.resolve_tz("Asia/Seoul"))[0].ts
    utc = ts.parse_sync_events(p, tz=ts.resolve_tz("+00:00"))[0].ts
    assert utc - kst == pytest.approx(9 * 3600)
    assert kst == pytest.approx(
        datetime(2026, 7, 21, 14, 57, 2, 388000, tzinfo=KST).timestamp()
    )


def test_extract_ntp_responses_warns_on_partial_output(monkeypatch):
    """tshark 가 실패코드로 끝났는데 부분 출력이 있으면 조용히 쓰면 안 된다."""
    row = (
        "1\t1753077430.0\tJul 21, 2026 05:57:35.000233528 UTC\t"
        "Jul 21, 2026 05:57:35.004315599 UTC\t192.168.0.10\n"
    )

    class _Proc:
        returncode = 2
        stdout = row
        stderr = "tshark: The file appears to have been cut short."

    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: _Proc())
    rows, warnings = ts.extract_ntp_responses("x.pcap")
    assert len(rows) == 1
    assert len(warnings) == 1
    assert "cut short" in warnings[0]


def test_extract_ntp_responses_raises_when_nothing_usable(monkeypatch):
    class _Proc:
        returncode = 2
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="tshark 실패"):
        ts.extract_ntp_responses("x.pcap")


def test_extract_ntp_responses_no_warning_on_success(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: _Proc())
    rows, warnings = ts.extract_ntp_responses("x.pcap")
    assert rows == [] and warnings == []


def test_build_ntp_tshark_cmd_decryption_flags():
    plain = ts.build_ntp_tshark_cmd("x.pcap")
    assert "wlan.enable_decryption:TRUE" not in plain
    enc = ts.build_ntp_tshark_cmd("x.pcap", ssid="S", passphrase="P")
    assert "wlan.enable_decryption:TRUE" in enc
    assert 'uat:80211_keys:"wpa-pwd","P:S"' in enc


# --------------------------------------------------------------------------
# sys.log 파싱 · 매칭
# --------------------------------------------------------------------------


def test_parse_sync_events(tmp_path):
    p = tmp_path / "sys.log"
    p.write_text(
        "2026-07-21 14:57:02.337 systemd-timesyncd[info] No network connectivity.\n"
        "2026-07-21 14:57:02.388 systemd-timesyncd[info] Contacted time server 192.168.0.10:123.\n"
        "2026-07-21 14:57:35.032 systemd-timesyncd[info] Contacted time server 192.168.0.10:123.\n",
        encoding="utf-8",
    )
    events = ts.parse_sync_events(p, tz=KST)
    assert [e.line_no for e in events] == [2, 3]
    assert events[0].ts == pytest.approx(
        datetime(2026, 7, 21, 14, 57, 2, 388000, tzinfo=KST).timestamp()
    )


def _resp(frame_no, arrival, org, xmt):
    return ts.NtpResponse(frame_no=frame_no, arrival=arrival, org=org, xmt=xmt)


def test_match_events_uses_org_and_is_one_to_one():
    events = [ts.SyncEvent(1, 100.4, ""), ts.SyncEvent(2, 200.4, "")]
    responses = [
        _resp(10, 76.0, 100.0, 100.1),  # 이벤트1 과 org 차 0.4
        _resp(11, 76.5, 100.2, 100.3),  # 이벤트1 과 org 차 0.2 -> 이쪽이 더 가깝다
        _resp(12, 176.0, 200.0, 200.1),
    ]
    matches = ts.match_events(events, responses, tolerance=1.0)
    assert len(matches) == 2
    assert matches[0].response.frame_no == 11
    assert matches[1].response.frame_no == 12


def test_match_events_does_not_reuse_a_response():
    """이벤트 2건이 같은 응답에 몰리면 안 된다."""
    events = [ts.SyncEvent(1, 100.0, ""), ts.SyncEvent(2, 100.1, "")]
    responses = [_resp(10, 76.0, 100.0, 100.05)]
    matches = ts.match_events(events, responses, tolerance=1.0)
    assert len(matches) == 1


def _resp_dst(frame_no, arrival, org, xmt, dst):
    return ts.NtpResponse(frame_no=frame_no, arrival=arrival, org=org, xmt=xmt, dst=dst)


def test_match_events_filters_by_destination():
    events = [ts.SyncEvent(1, 100.0, "")]
    responses = [
        _resp_dst(10, 76.0, 100.05, 100.1, "192.168.0.22"),  # 더 가깝지만 남의 장비
        _resp_dst(11, 76.5, 100.40, 100.5, "192.168.0.21"),
    ]
    assert ts.match_events(events, responses, tolerance=1.0)[0].response.frame_no == 10
    own = ts.match_events(events, responses, tolerance=1.0, dst="192.168.0.21")
    assert own[0].response.frame_no == 11


def test_analyze_offset_picks_own_device_and_drops_foreign(monkeypatch):
    """회귀: 남의 장비 프레임에 붙으면 device_minus_ntp(장치 시계 검증)가 오염된다."""
    responses = [
        # 우리 장비(.21): arrival = xmt - 10 (캡처가 10초 뒤처짐)
        _resp_dst(1, 90.00, 100.00, 100.00, "192.168.0.21"),
        _resp_dst(2, 110.00, 120.00, 120.00, "192.168.0.21"),
        _resp_dst(3, 130.00, 140.00, 140.00, "192.168.0.21"),
        # 남의 장비(.22): 우연히 tolerance 안에 들어오지만 arrival-xmt 가 -9.9 로 다르다
        _resp_dst(4, 90.90, 100.80, 100.80, "192.168.0.22"),
    ]
    events = [ts.SyncEvent(1, 100.05, ""), ts.SyncEvent(2, 120.05, ""), ts.SyncEvent(3, 140.05, "")]
    res = ts.analyze_offset("x.pcap", responses, [], events, tolerance=1.0)
    assert res.device_ip == "192.168.0.21"
    assert res.matched == 3
    assert res.capture_minus_ntp.median == pytest.approx(-10.0)
    # 남의 프레임(-9.9)이 섞였다면 device_minus_ntp 범위가 무너진다
    assert res.device_minus_ntp_upper.min == pytest.approx(0.05)
    assert res.device_minus_ntp_upper.max == pytest.approx(0.05)


def test_match_events_respects_tolerance():
    events = [ts.SyncEvent(1, 100.0, "")]
    responses = [_resp(10, 76.0, 105.0, 105.1)]
    assert ts.match_events(events, responses, tolerance=1.0) == []
    assert len(ts.match_events(events, responses, tolerance=10.0)) == 1


def test_match_capture_minus_ntp_uses_xmt_not_org():
    """오프셋은 반드시 xmt(서버 송신시각) 기준이어야 한다."""
    m = ts.match_events(
        [ts.SyncEvent(1, 100.5, "")],
        [_resp(10, 75.0, 100.0, 100.2)],
        tolerance=1.0,
    )[0]
    assert m.capture_minus_ntp == pytest.approx(75.0 - 100.2)
    assert m.device_minus_ntp == pytest.approx(100.5 - 100.2)


# --------------------------------------------------------------------------
# 통계
# --------------------------------------------------------------------------


def test_summarize_and_drift():
    assert ts.summarize([]) is None
    s = ts.summarize([1.0, 2.0, 3.0, 4.0])
    assert s.n == 4 and s.median == pytest.approx(2.5)
    assert s.min == 1.0 and s.max == 4.0
    assert s.iqr == pytest.approx(s.q3 - s.q1)


def test_linear_drift_ppm_detects_slope():
    # 1000초 동안 오프셋이 0.01초 증가 = 10 ppm
    pts = [(t, 5.0 + 1e-5 * t) for t in range(0, 1001, 100)]
    assert ts.linear_drift_ppm(pts) == pytest.approx(10.0, rel=1e-6)
    assert ts.linear_drift_ppm([(0.0, 1.0)]) is None


def test_offset_result_log_shift_is_none_without_data():
    r = ts.OffsetResult("x.pcap", 0, 0, None, None, None, None)
    assert r.log_shift_seconds is None
    assert r.as_dict()["log_shift_seconds"] is None


# --------------------------------------------------------------------------
# 타임스탬프 이동
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,delta,want",
    [
        # 소수 자릿수 보존
        ("2026-07-21 14:57:01.205", -24.317308, "2026-07-21 14:56:36.888"),
        # 소수 없음 -> 가장 가까운 초로 반올림
        ("2026-07-21 14:57:02", -24.317308, "2026-07-21 14:56:38"),
        # 양수 오프셋
        ("2026-07-21 14:57:01.205", 181.406703, "2026-07-21 15:00:02.612"),
        # 자정 넘김
        ("2026-07-21 23:59:59.900", 0.2, "2026-07-22 00:00:00.100"),
        # 반올림 올림이 초로 캐리
        ("2026-07-21 14:57:01.999", 0.0006, "2026-07-21 14:57:02.000"),
        # 마이크로초 6자리
        ("2026-07-21 14:57:01.123456", -1.0, "2026-07-21 14:57:00.123456"),
    ],
)
def test_shift_timestamp_text(raw, delta, want):
    assert ts._shift_timestamp_text(raw, delta) == want


def test_shift_line_all_default_formats():
    pats = ts.compile_patterns()
    cases = [
        ("2026-07-21 14:57:01.205 kernel[alert] wlan\n", "2026-07-21 14:56:37.205 kernel[alert] wlan\n"),
        ("[2026-07-21 14:57:02]\n", "[2026-07-21 14:56:38]\n"),
        ("===== 2026-07-21 14:57:04 =====\n", "===== 2026-07-21 14:56:40 =====\n"),
        ("2026-07-21 14:57:01\tWLAN: Login\n", "2026-07-21 14:56:37\tWLAN: Login\n"),
    ]
    for src, want in cases:
        got, changed = ts.shift_line(src, -24.0, pats)
        assert changed is True
        assert got == want


def test_shift_line_ignores_body_dates():
    """본문 속 날짜는 절대 이동시키면 안 된다 (AP 로그의 NTP: Setting clock 등)."""
    pats = ts.compile_patterns()
    line = "2026-07-21 14:57:01\tNTP: Setting clock (2015-01-01 00:00:07)\n"
    got, changed = ts.shift_line(line, -24.0, pats)
    assert changed is True
    assert got == "2026-07-21 14:56:37\tNTP: Setting clock (2015-01-01 00:00:07)\n"


def test_shift_line_survives_overflowing_offset():
    """회귀: 거대한 오프셋의 OverflowError 가 2단계를 중단시키고 반쪽 출력을 남겼다."""
    pats = ts.compile_patterns()
    line = "2026-07-21 14:57:01.205 x\n"
    got, changed = ts.shift_line(line, 1e15, pats)
    assert changed is False
    assert got == line


def test_compile_patterns_requires_ts_group():
    with pytest.raises(ValueError, match=r"\(\?P<ts>"):
        ts.compile_patterns([r"^\d{4}"])
    with pytest.raises(ValueError, match="컴파일 실패"):
        ts.compile_patterns([r"^(?P<ts>["])


def test_parse_sync_events_skips_malformed_dates(tmp_path):
    """회귀: 깨진 날짜 한 줄이 1단계 전체를 ValueError 로 죽였다."""
    p = tmp_path / "sys.log"
    p.write_text(
        "2026-13-45 99:99:99.000 Contacted time server 192.168.0.10:123.\n"
        "2026-07-21 14:57:02.388 Contacted time server 192.168.0.10:123.\n",
        encoding="utf-8",
    )
    events = ts.parse_sync_events(p, tz=KST)
    assert len(events) == 1
    assert events[0].line_no == 2


def test_compile_patterns_rejects_pattern_without_ts_group():
    """(?P<ts>) 없는 정규식은 shift_line 에서 IndexError 로 죽으며 반쪽 출력을 남긴다."""
    with pytest.raises(ValueError, match=r"\(\?P<ts>"):
        ts.compile_patterns([r"^\d{4}-\d{2}-\d{2}"])
    with pytest.raises(ValueError, match="컴파일 실패"):
        ts.compile_patterns([r"^(?P<ts>["])


def test_shift_line_survives_out_of_range_offset():
    """delta 가 datetime 범위를 넘겨도 예외를 밖으로 던지면 안 된다."""
    pats = ts.compile_patterns()
    line = "2026-07-21 14:57:01.205 x\n"
    got, changed = ts.shift_line(line, 1e15, pats)
    assert changed is False
    assert got == line


def test_parse_sync_events_skips_malformed_line(tmp_path):
    """깨진 날짜 한 줄 때문에 1단계 전체가 죽으면 안 된다."""
    p = tmp_path / "sys.log"
    p.write_text(
        "2026-07-21 14:57:02.388 Contacted time server 192.168.0.10:123.\n"
        "2026-13-45 99:99:99.000 Contacted time server 192.168.0.10:123.\n"
        "2026-07-21 14:57:35.032 Contacted time server 192.168.0.10:123.\n",
        encoding="utf-8",
    )
    events = ts.parse_sync_events(p, tz=KST)
    assert [e.line_no for e in events] == [1, 3]


def test_shift_line_passes_through_untimestamped():
    pats = ts.compile_patterns()
    line = "00| 048 | -62 | 012 | 00:80:4c:e1:09:cb | I2DM   N   | CANTOPS_TEST\n"
    got, changed = ts.shift_line(line, -24.0, pats)
    assert changed is False
    assert got == line


def test_shift_log_file_roundtrip_and_counts(tmp_path):
    src = tmp_path / "in.log"
    src.write_text(
        "2026-07-21 14:57:01.205 first\n"
        "no timestamp here\n"
        "[2026-07-21 14:57:02] second\n",
        encoding="utf-8",
    )
    dst = tmp_path / "out" / "in.log"
    total, changed = ts.shift_log_file(src, dst, -24.317308)
    assert (total, changed) == (3, 2)
    lines = dst.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("2026-07-21 14:56:36.888 first")
    assert lines[1] == "no timestamp here"
    assert lines[2].startswith("[2026-07-21 14:56:38] second")


def test_shift_log_file_is_reversible(tmp_path):
    """+d 적용 후 -d 를 적용하면 ms 해상도 줄은 원본으로 돌아와야 한다."""
    src = tmp_path / "a.log"
    src.write_text("2026-07-21 14:57:01.205 x\n2026-07-21 15:03:59.001 y\n", encoding="utf-8")
    mid, back = tmp_path / "m.log", tmp_path / "b.log"
    ts.shift_log_file(src, mid, 181.5)
    ts.shift_log_file(mid, back, -181.5)
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_shift_log_file_dry_run_writes_nothing(tmp_path):
    src = tmp_path / "a.log"
    src.write_text("2026-07-21 14:57:01.205 x\n", encoding="utf-8")
    dst = tmp_path / "out" / "a.log"
    total, changed = ts.shift_log_file(src, dst, 1.0, dry_run=True)
    assert (total, changed) == (1, 1)
    assert not dst.exists()


def test_shift_log_file_preserves_crlf_and_invalid_bytes(tmp_path):
    src = tmp_path / "a.log"
    src.write_bytes(b"2026-07-21 14:57:01.205 caf\xe9\r\nplain\r\n")
    dst = tmp_path / "out" / "a.log"
    ts.shift_log_file(src, dst, 0.0)
    assert dst.read_bytes() == b"2026-07-21 14:57:01.205 caf\xe9\r\nplain\r\n"


# --------------------------------------------------------------------------
# 설정 JSON
# --------------------------------------------------------------------------


def test_extract_options_plain_dict():
    doc = {"ssid": "S", "psk": "P", "tolerance": 2.0}
    assert ts.extract_options(doc) == doc


def test_extract_options_plain_dict_keeps_unknown_keys():
    """오타를 load_config 가 잡을 수 있도록 걸러내지 않고 그대로 넘긴다."""
    assert ts.extract_options({"ssid": "S", "무관한키": 1}) == {"ssid": "S", "무관한키": 1}


def test_extract_options_legacy_result_without_options_block():
    """options 블록이 없는 구버전 결과 JSON 은 옵션 없음으로 본다 (에러 아님)."""
    assert ts.extract_options({"generated_at": "x", "sources": [], "dataset": "d"}) == {}


def test_extract_options_from_stage1_result():
    """1단계 결과 JSON 을 그대로 --config 로 되먹일 수 있어야 한다."""
    doc = {"generated_at": "x", "sources": [], "options": {"ssid": "S", "tolerance": 3.0}}
    assert ts.extract_options(doc) == {"ssid": "S", "tolerance": 3.0}


def test_extract_options_from_named_section():
    doc = {"other": 1, "timesync": {"ssid": "S"}}
    assert ts.extract_options(doc) == {"ssid": "S"}


def test_extract_options_rejects_non_dict():
    with pytest.raises(ValueError):
        ts.extract_options([1, 2, 3])


def _write_cfg(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_config_explicit(tmp_path):
    cfg = tmp_path / "custom.json"
    _write_cfg(cfg, {"ssid": "S"})
    opts, used = ts.load_config(cfg)
    assert opts == {"ssid": "S"}
    assert used == cfg


def test_load_config_autodiscovers_in_dataset_dir(tmp_path):
    _write_cfg(tmp_path / ts.CONFIG_FILENAME, {"tolerance": 2.5})
    opts, used = ts.load_config(None, search_from=tmp_path)
    assert opts == {"tolerance": 2.5}
    assert used == tmp_path / ts.CONFIG_FILENAME


def test_load_config_autodiscovers_in_parent(tmp_path):
    """2단계는 <dataset>/1호기 를 받으므로 부모의 설정을 집어야 한다."""
    logdir = tmp_path / "1호기"
    logdir.mkdir()
    _write_cfg(tmp_path / ts.CONFIG_FILENAME, {"source": "유선"})
    opts, used = ts.load_config(None, search_from=logdir)
    assert opts == {"source": "유선"}
    assert used == tmp_path / ts.CONFIG_FILENAME


def test_load_config_auto_disabled(tmp_path):
    _write_cfg(tmp_path / ts.CONFIG_FILENAME, {"tolerance": 2.5})
    assert ts.load_config(None, search_from=tmp_path, auto=False) == ({}, None)


def test_load_config_missing_explicit_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ts.load_config(tmp_path / "nope.json")


def test_load_config_rejects_unknown_key(tmp_path):
    cfg = tmp_path / "c.json"
    _write_cfg(cfg, {"ssid": "S", "tolerence": 1.0})  # 오타
    with pytest.raises(ValueError, match="tolerence"):
        ts.load_config(cfg)


def test_load_config_reports_bad_json(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ValueError, match="파싱 실패"):
        ts.load_config(cfg)


def test_merge_options_precedence():
    merged = ts.merge_options({"ssid": "cli", "tolerance": None}, {"ssid": "cfg", "tolerance": 5.0})
    assert merged["ssid"] == "cli"  # CLI 우선
    assert merged["tolerance"] == 5.0  # CLI 미지정 -> 설정
    assert merged["sync_pattern"] == ts.DEFAULT_SYNC_PATTERN  # 둘 다 없음 -> 기본값


def test_merge_options_coerces_types():
    merged = ts.merge_options({}, {"tolerance": "2.5", "glob": "*.log"})
    assert merged["tolerance"] == 2.5
    assert merged["glob"] == ["*.log"]


def test_merge_options_rejects_non_numeric_tolerance():
    with pytest.raises(ValueError, match="tolerance"):
        ts.merge_options({}, {"tolerance": "abc"})


def test_merge_options_never_shares_mutable_defaults():
    """설정이 비어 기본값이 그대로 쓰일 때도 전역 리스트를 참조하면 안 된다."""
    merged = ts.merge_options({}, {})
    assert merged["glob"] is not ts.DEFAULT_OPTIONS["glob"]
    merged["glob"].append("*.bogus")
    merged["pattern"].append("^x")
    assert ts.DEFAULT_OPTIONS["glob"] == list(ts.DEFAULT_LOG_GLOBS)
    assert ts.DEFAULT_OPTIONS["pattern"] == []


def test_merge_options_does_not_mutate_defaults():
    merged = ts.merge_options({}, {"glob": ["*.x"]})
    merged["glob"].append("*.y")
    assert ts.DEFAULT_OPTIONS["glob"] == list(ts.DEFAULT_LOG_GLOBS)


def test_merge_options_copies_mutable_defaults_when_unset():
    """회귀: 설정이 비면 리스트 옵션이 모듈 전역 기본값을 그대로 참조했다."""
    merged = ts.merge_options({}, {})
    assert merged["glob"] is not ts.DEFAULT_OPTIONS["glob"]
    merged["glob"].append("*.oops")
    merged["pattern"].append("^x")
    assert ts.DEFAULT_OPTIONS["glob"] == list(ts.DEFAULT_LOG_GLOBS)
    assert ts.DEFAULT_OPTIONS["pattern"] == []


# --------------------------------------------------------------------------
# 디렉터리 탐색
# --------------------------------------------------------------------------


def test_find_helpers(tmp_path):
    (tmp_path / "1호기").mkdir()
    (tmp_path / "wireshark" / "유선").mkdir(parents=True)
    (tmp_path / "1호기" / "sys.log").write_text("x", encoding="utf-8")
    (tmp_path / "1호기" / "wpa.log").write_text("x", encoding="utf-8")
    (tmp_path / "wireshark" / "유선" / "a.pcapng").write_bytes(b"x")
    (tmp_path / "b.pcap").write_bytes(b"x")
    (tmp_path / "note.md").write_text("x", encoding="utf-8")

    assert ts.find_syslog(tmp_path) == tmp_path / "1호기" / "sys.log"
    assert {p.name for p in ts.find_pcaps(tmp_path)} == {"a.pcapng", "b.pcap"}
    assert {p.name for p in ts.find_log_files(tmp_path)} == {"sys.log", "wpa.log"}


def test_find_helpers_accept_file_path(tmp_path):
    f = tmp_path / "only.pcap"
    f.write_bytes(b"x")
    assert ts.find_pcaps(f) == [f]
    assert ts.find_syslog(f) == f


def test_find_log_files_drops_results_outside_root(tmp_path):
    """glob 이 '..' 로 상위를 타고 올라가도 root 밖 파일은 대상이 되면 안 된다."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "in.log").write_text("x", encoding="utf-8")
    (tmp_path / "outside.log").write_text("x", encoding="utf-8")
    found = ts.find_log_files(root, ("../*.log",))
    assert all(p.resolve().is_relative_to(root.resolve()) for p in found)
    assert not any(p.name == "outside.log" for p in found)


def test_pcap_shift_seconds_inverts_sign():
    """캡처가 뒤처져 있으면(-) pcap 에는 더해야(+) NTP 진실에 맞는다."""
    assert ts.pcap_shift_seconds(-24.317308) == pytest.approx(24.317308)
    assert ts.pcap_shift_seconds(181.406703) == pytest.approx(-181.406703)
    assert ts.pcap_shift_seconds(0.0) == 0.0


def test_build_editcap_cmd():
    cmd = ts.build_editcap_cmd("a.pcapng", "b.pcapng", 24.317308)
    assert cmd[0] == "editcap"
    assert cmd[1] == "-t"
    assert float(cmd[2]) == pytest.approx(24.317308)
    assert cmd[3:] == ["a.pcapng", "b.pcapng"]
    assert ts.build_editcap_cmd("a", "b", 1.0, editcap_path="/opt/editcap")[0] == "/opt/editcap"


def test_shift_pcap_file_dry_run_does_not_run_editcap(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: called.append(a))
    ts.shift_pcap_file("a.pcapng", tmp_path / "out" / "a.pcapng", 1.0, dry_run=True)
    assert called == []
    assert not (tmp_path / "out").exists()


def test_shift_pcap_file_cleans_up_on_failure(monkeypatch, tmp_path):
    """editcap 이 실패하면 만들다 만 출력을 남기면 안 된다."""
    dst = tmp_path / "out" / "a.pcapng"

    class _Proc:
        returncode = 2
        stdout = ""
        stderr = "editcap: unsupported"

    def _run(*a, **k):
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(b"partial")
        return _Proc()

    monkeypatch.setattr(ts.subprocess, "run", _run)
    with pytest.raises(RuntimeError, match="editcap 실패"):
        ts.shift_pcap_file("a.pcapng", dst, 1.0)
    assert not dst.exists()


def test_device_clock_lag_goes_to_log_warnings_only():
    """회귀: 장치 시계 문제로 pcap 보정까지 막히면 안 된다.

    pcap 을 NTP 서버 시각에 맞추는 데 장치 시계는 무관하다.
    """
    # device_minus_ntp = event.ts - xmt 가 -0.2 (장치가 뒤처짐)
    responses = [
        _resp_dst(i, 90.0 + 20 * i, 100.0 + 20 * i, 100.0 + 20 * i, "192.168.0.21")
        for i in range(4)
    ]
    events = [ts.SyncEvent(i, 99.8 + 20 * i, "") for i in range(4)]
    res = ts.analyze_offset("x.pcap", responses, [], events, tolerance=1.0)
    assert res.matched == 4
    assert res.device_minus_ntp_upper.median == pytest.approx(-0.2)
    assert any("뒤처져" in w for w in res.log_warnings), res.log_warnings
    assert res.warnings == [], f"pcap 보정을 막는 warnings 로 새면 안 된다: {res.warnings}"


def test_truncated_pcap_goes_to_notes_not_warnings(monkeypatch):
    """잘린 pcap 은 오프셋을 무효화하지 않는다 — editcap 이 읽힌 부분을 정상 복구한다."""
    row = (
        "1\t1000.500\tJan 1, 1970 00:16:40.100000000 UTC\t"
        "Jan 1, 1970 00:16:40.200000000 UTC\t192.168.0.10\t192.168.0.21\n"
    )

    class _Proc:
        returncode = 2
        stdout = row
        stderr = "editcap: appears to be damaged or corrupt."

    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: _Proc())
    res = ts.measure_offset_best("x.pcap", [("1호기", [ts.SyncEvent(1, 1000.3, "")])], tolerance=1.0)
    assert res.matched == 1
    assert any("damaged" in n for n in res.notes), res.notes
    assert not [w for w in res.warnings if "damaged" in w], res.warnings


def test_measure_offset_best_picks_matching_syslog(monkeypatch):
    """캡처 구간과 겹치는 로그를 골라야 한다 (1호기가 항상 정답은 아니다)."""
    row = (
        "1\t1000.500\tJan 1, 1970 00:16:40.100000000 UTC\t"
        "Jan 1, 1970 00:16:40.200000000 UTC\t192.168.0.10\n"
    )

    class _Proc:
        returncode = 0
        stdout = row
        stderr = ""

    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: _Proc())
    stale = ("1호기", [ts.SyncEvent(1, 500.0, "")])  # 겹치지 않음
    good = ("2호기", [ts.SyncEvent(1, 1000.3, "")])  # org=1000.1 과 0.2초 차
    res = ts.measure_offset_best("x.pcap", [stale, good], tolerance=1.0)
    assert res.syslog == "2호기"
    assert res.matched == 1
    assert res.capture_minus_ntp.median == pytest.approx(1000.5 - 1000.2)


def test_measure_offset_best_does_not_warn_about_syslog_choice(monkeypatch):
    """회귀: 로그 선택 안내를 warnings 에 넣으면 2단계가 적용을 거부한다."""
    row = (
        "1\t1000.500\tJan 1, 1970 00:16:40.100000000 UTC\t"
        "Jan 1, 1970 00:16:40.200000000 UTC\t192.168.0.10\n"
    )

    class _Proc:
        returncode = 0
        stdout = row
        stderr = ""

    monkeypatch.setattr(ts.subprocess, "run", lambda *a, **k: _Proc())
    res = ts.measure_offset_best(
        "x.pcap",
        [("1호기", [ts.SyncEvent(1, 500.0, "")]), ("2호기", [ts.SyncEvent(1, 1000.3, "")])],
        tolerance=1.0,
    )
    assert res.matched == 1
    assert res.syslog == "2호기"  # 선택 정보는 전용 필드에 담긴다
    # warnings 는 "이 오프셋을 쓰지 말라"는 뜻이므로 로그 선택 안내가 섞이면 안 된다.
    # (표본 부족 같은 진짜 경고는 정당하게 남는다)
    assert not [w for w in res.warnings if "sys.log 후보" in w], res.warnings


def test_find_syslogs_returns_all_devices(tmp_path):
    for dev in ("1호기", "2호기", "3호기"):
        d = tmp_path / dev
        d.mkdir()
        (d / "sys.log").write_text("x", encoding="utf-8")
    found = ts.find_syslogs(tmp_path)
    assert len(found) == 3
    assert {p.parent.name for p in found} == {"1호기", "2호기", "3호기"}
    # 단수형은 하위호환 — 첫 번째를 돌려준다
    assert ts.find_syslog(tmp_path) == found[0]


def test_paths_overlap_both_directions(tmp_path):
    """회귀: --out 이 입력의 상위여도 형제 원본이 통째로 덮어써지던 문제."""
    base = tmp_path / "a" / "logs"
    base.mkdir(parents=True)
    assert ts.paths_overlap(base, base) is True
    assert ts.paths_overlap(base / "out", base) is True  # out 이 안
    assert ts.paths_overlap(tmp_path / "a", base) is True  # out 이 위
    assert ts.paths_overlap(tmp_path / "b", base) is False  # 무관


def test_plan_output_paths_flags_escapers(tmp_path):
    base = tmp_path / "logs"
    base.mkdir()
    inside = base / "a.log"
    inside.write_text("x", encoding="utf-8")
    outside = tmp_path / "b.log"
    outside.write_text("x", encoding="utf-8")
    outdir = tmp_path / "out"

    pairs, escaped = ts.plan_output_paths([inside, outside], base, outdir)
    assert [p[0] for p in pairs] == [inside]
    assert pairs[0][1] == outdir / "a.log"
    assert escaped == [outside]


# --------------------------------------------------------------------------
# CLI 통합 (tshark 불필요)
# --------------------------------------------------------------------------

import subprocess  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

APPLY_CLI = Path(__file__).resolve().parent.parent / "scripts" / "timesync-apply.py"


def _run(*argv):
    return subprocess.run(
        [sys.executable, str(APPLY_CLI), *argv], capture_output=True, text=True
    )


def _logdir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "a.log").write_text("2026-07-21 14:57:01.205 hello\n", encoding="utf-8")
    return d


def test_cli_apply_reads_offset_from_config(tmp_path):
    """1단계 결과 JSON 하나로 옵션과 오프셋을 모두 읽는다."""
    cfg = tmp_path / "result.json"
    _write_cfg(
        cfg,
        {
            "options": {"source": "유선", "glob": ["*.log"]},
            "sources": [
                {"pcap": "a/유선/x.pcapng", "log_shift_seconds": -24.0, "warnings": []},
                {"pcap": "a/무선/y.pcapng", "log_shift_seconds": -2.0, "warnings": []},
            ],
        },
    )
    out = tmp_path / "out"
    r = _run(str(_logdir(tmp_path)), "--config", str(cfg), "--out", str(out))
    assert r.returncode == 0, r.stderr
    assert "-24.000000" in r.stdout  # options.source='유선' 이 선택됨
    assert (out / "a.log").read_text(encoding="utf-8").startswith("2026-07-21 14:56:37.205")


def test_cli_apply_cli_overrides_config(tmp_path):
    cfg = tmp_path / "result.json"
    _write_cfg(
        cfg,
        {
            "options": {"source": "유선"},
            "sources": [
                {"pcap": "a/유선/x.pcapng", "log_shift_seconds": -24.0, "warnings": []},
                {"pcap": "a/무선/y.pcapng", "log_shift_seconds": -2.0, "warnings": []},
            ],
        },
    )
    r = _run(
        str(_logdir(tmp_path)), "--config", str(cfg),
        "--source", "무선", "--out", str(tmp_path / "out"),
    )
    assert r.returncode == 0, r.stderr
    assert "-2.000000" in r.stdout


def test_cli_apply_never_writes_outside_out_dir(tmp_path):
    """회귀: --glob '../*.log' 로 입력 트리 밖 원본이 제자리 파괴되던 버그."""
    d = _logdir(tmp_path)
    sibling = tmp_path / "sibling.log"
    original = "2026-07-21 10:00:00.000 SIBLING-ORIGINAL\n"
    sibling.write_text(original, encoding="utf-8")

    r = _run(
        str(d), "--offset", "3600", "--no-config",
        "--glob", "../*.log", "--out", str(tmp_path / "out"),
    )
    assert sibling.read_text(encoding="utf-8") == original, "원본이 덮어써졌다"
    assert r.returncode != 0 or "sibling" not in r.stdout


def test_cli_apply_rejects_out_above_input_tree(tmp_path):
    """회귀: --out 이 입력의 상위면 형제 원본이 내용째로 교체되던 버그."""
    d = _logdir(tmp_path)
    sibling = tmp_path / "a.log"  # logdir 안의 a.log 와 같은 이름
    original = "2026-07-21 10:00:00.000 SIBLING-ORIGINAL\n"
    sibling.write_text(original, encoding="utf-8")

    r = _run(str(d), "--offset", "3600", "--no-config", "--out", str(tmp_path))
    assert r.returncode == 2
    assert "겹친다" in r.stderr
    assert sibling.read_text(encoding="utf-8") == original


def _warned_result_json(tmp_path, shift=-24.0):
    cfg = tmp_path / "result.json"
    _write_cfg(
        cfg,
        {
            "options": {},
            "sources": [
                {
                    "pcap": "a/x.pcapng",
                    "log_shift_seconds": shift,
                    "warnings": ["장치 로그 시계가 NTP 서버보다 최소 5.000s 뒤처져 있다"],
                }
            ],
        },
    )
    return cfg


def test_cli_apply_refuses_when_stage1_warned(tmp_path):
    """1단계가 '그대로 쓰지 말라'고 한 오프셋을 조용히 적용하면 안 된다."""
    out = tmp_path / "out"
    r = _run(
        str(_logdir(tmp_path)), "--config", str(_warned_result_json(tmp_path)),
        "--out", str(out),
    )
    assert r.returncode == 2
    assert "--force" in r.stderr
    assert not out.exists()


def test_cli_apply_force_overrides_stage1_warning(tmp_path):
    out = tmp_path / "out"
    r = _run(
        str(_logdir(tmp_path)), "--config", str(_warned_result_json(tmp_path)),
        "--out", str(out), "--force",
    )
    assert r.returncode == 0, r.stderr
    assert (out / "a.log").exists()


def test_cli_apply_labels_config_injected_offset_honestly(tmp_path):
    """자동 탐색된 설정의 offset 을 '직접 지정'이라 표기하면 거짓말이다."""
    _write_cfg(tmp_path / ts.CONFIG_FILENAME, {"offset": -5.0})
    r = _run(str(_logdir(tmp_path)), "--out", str(tmp_path / "out"))
    assert r.returncode == 0, r.stderr
    assert "설정 파일의 offset 키" in r.stdout
    assert "직접 지정" not in r.stdout.split("출처:")[1].split("\n")[0]


def test_cli_apply_rejects_out_as_parent_of_input(tmp_path):
    """회귀: --out 이 입력의 상위면 형제 원본이 내용째로 덮어써지던 문제."""
    d = _logdir(tmp_path)
    sibling = tmp_path / "a.log"  # d/a.log 와 같은 이름, 다른 내용
    original = "2026-07-21 09:00:00.000 SIBLING-ORIGINAL\n"
    sibling.write_text(original, encoding="utf-8")

    r = _run(str(d), "--offset", "3600", "--no-config", "--out", str(tmp_path))
    assert r.returncode == 2
    assert "겹친다" in r.stderr
    assert sibling.read_text(encoding="utf-8") == original


def test_cli_apply_refuses_offset_carrying_stage1_warning(tmp_path):
    """1단계가 '쓰지 말라'고 한 오프셋을 조용히 적용하면 안 된다."""
    doc = tmp_path / "result.json"
    _write_cfg(
        doc,
        {
            "sources": [
                {
                    "pcap": "x.pcapng",
                    "log_shift_seconds": -1.5,
                    "warnings": ["장치 로그 시계가 NTP 서버보다 뒤처져 있다"],
                }
            ]
        },
    )
    d = _logdir(tmp_path)
    out = tmp_path / "out"

    blocked = _run(str(d), "--offset-file", str(doc), "--no-config", "--out", str(out))
    assert blocked.returncode == 2
    assert "--force" in blocked.stderr
    assert not out.exists()

    forced = _run(
        str(d), "--offset-file", str(doc), "--no-config", "--out", str(out), "--force"
    )
    assert forced.returncode == 0, forced.stderr
    assert (out / "a.log").exists()


def test_cli_apply_reports_config_injected_offset_origin(tmp_path):
    """자동 탐색된 설정이 넣은 오프셋을 '직접 지정'이라 표기하면 거짓말이 된다."""
    d = _logdir(tmp_path)
    _write_cfg(d / ts.CONFIG_FILENAME, {"timesync": {"offset": -7.5}})
    r = _run(str(d), "--out", str(tmp_path / "out"))
    assert r.returncode == 0, r.stderr
    assert "설정 파일의 offset 키" in r.stdout


def test_cli_apply_rejects_malformed_offset_document(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    r = _run(
        str(_logdir(tmp_path)), "--offset-file", str(bad), "--no-config",
        "--out", str(tmp_path / "out"),
    )
    assert r.returncode == 2
    assert "읽을 수 없다" in r.stderr


def test_cli_apply_rejects_out_inside_input_tree(tmp_path):
    """출력이 입력 트리 안이면 이중 보정 위험 — 거부해야 한다."""
    d = _logdir(tmp_path)
    r = _run(str(d), "--offset", "-1.0", "--no-config", "--out", str(d / "shifted"))
    assert r.returncode == 2
    assert "입력 트리" in r.stderr


def test_cli_apply_print_config_emits_loadable_json(tmp_path):
    cfg = tmp_path / "timesync.json"
    _write_cfg(cfg, {"timesync": {"source": "유선", "offset": -3.5}})
    r = _run(str(_logdir(tmp_path)), "--config", str(cfg), "--print-config")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["timesync"]["source"] == "유선"
    assert doc["timesync"]["offset"] == -3.5
    # 출력이 다시 설정으로 읽혀야 한다 (왕복)
    round_trip = tmp_path / "again.json"
    round_trip.write_text(r.stdout, encoding="utf-8")
    opts, _ = ts.load_config(round_trip)
    assert opts["source"] == "유선"
