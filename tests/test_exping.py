"""analyzer.core.exping 단위 테스트.

역공학으로 확정한 규칙(정수 ms 보정 0.276, 응답 상한 1초, 꼬리 무응답 삭제,
시트명 31자 절삭)을 회귀로 고정한다. 근거는 docs/EXPING.md 참조.
"""

import csv
import datetime as dt
import io

import pytest

from analyzer.core import exping as ep


def _ex(t: float, target: str = "192.168.0.21", rtt: float | None = 0.001) -> ep.Exchange:
    return ep.Exchange(t, target, rtt)


# --------------------------------------------------------------------------
# ステータス 문자열
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rtt_ms, want",
    [
        (0.0, "Time:     0ms"),
        (0.7238, "Time:     0ms"),  # 0.7238 + 0.276 = 0.9998 -> 0
        (0.724, "Time:     1ms"),  # 경계 바로 위
        (1.0, "Time:     1ms"),
        (9.9, "Time:    10ms"),
        (72.77, "Time:    73ms"),
        (1234.0, "Time:  1234ms"),
    ],
)
def test_format_status_floors_with_offset(rtt_ms, want):
    assert ep.format_status(rtt_ms / 1000) == want


def test_format_status_timeout():
    assert ep.format_status(None) == ep.STATUS_TIMEOUT


def test_format_status_width_matches_reference():
    """기준 파일의 'Time:' 행은 모두 13자다 — %6d 폭이 무너지면 안 된다."""
    for ms in (0, 1, 10, 100, 1000):
        assert len(ep.format_status(ms / 1000)) == 13


def test_format_status_never_negative():
    """보정값을 음수로 줘도 음수 ms 를 적지 않는다."""
    assert ep.format_status(0.0001, offset_ms=-5.0) == "Time:     0ms"


def test_format_status_offset_is_tunable():
    assert ep.format_status(0.0007, offset_ms=0.0) == "Time:     0ms"
    assert ep.format_status(0.0007, offset_ms=0.5) == "Time:     1ms"


# --------------------------------------------------------------------------
# 시트/표 이름
# --------------------------------------------------------------------------


def test_sheet_names_short_base_keeps_full_name():
    assert ep.sheet_names("FXE3000_TEST1(1457_1515)") == (
        "FXE3000_TEST1(1457_1515) (2)",
        "FXE3000_TEST1(1457_1515)",
    )


def test_sheet_names_truncates_base_like_excel():
    """기준 파일 실측: 'FXA3000_RAIL_TEST1(1514_1534)' -> 'FXA3000_RAIL_TEST1(1514_153 (2)'."""
    dup, plain = ep.sheet_names("FXA3000_RAIL_TEST1(1514_1534)")
    assert dup == "FXA3000_RAIL_TEST1(1514_153 (2)"
    assert len(dup) == ep.SHEET_NAME_LIMIT
    assert plain == "FXA3000_RAIL_TEST1(1514_1534)"


def test_sheet_names_exact_boundary_is_not_truncated():
    base = "X" * (ep.SHEET_NAME_LIMIT - 4)  # + " (2)" == 정확히 31
    dup, _ = ep.sheet_names(base)
    assert dup == base + " (2)"
    assert len(dup) == ep.SHEET_NAME_LIMIT


def test_table_name_sanitises_and_strips_trailing_underscore():
    assert ep.table_name("FXE3000_TEST1(1457_1515)") == "FXE3000_TEST1_1457_1515"
    assert ep.table_name("a b.c") == "a_b_c"


def test_table_name_never_empty():
    """단어 문자가 없으면 빈 이름이 되어 엑셀이 거부한다."""
    assert ep.table_name("---") == "ExpingTable"
    assert ep.table_name("") == "ExpingTable"


# --------------------------------------------------------------------------
# 타임존 (os.environ/tzset 없이 처리한다 — tzset 은 POSIX 전용)
# --------------------------------------------------------------------------


def test_local_stamp_honours_explicit_tz():
    from datetime import timedelta, timezone

    epoch = 1784700837.5  # 2026-07-22 06:13:57.5 UTC
    assert ep.local_stamp(epoch, timezone.utc) == dt.datetime(2026, 7, 22, 6, 13, 57, 500000)
    kst = ep.local_stamp(epoch, timezone(timedelta(hours=9)))
    assert kst == dt.datetime(2026, 7, 22, 15, 13, 57, 500000)
    assert kst.tzinfo is None, "엑셀은 타임존 붙은 datetime 을 거부한다"


def test_exchanges_to_rows_uses_given_tz():
    from datetime import timedelta, timezone

    rows = ep.exchanges_to_rows([_ex(1784700837.9)], tz=timezone(timedelta(hours=9)))
    assert rows[0][1] == dt.datetime(2026, 7, 22, 15, 13, 57)


# --------------------------------------------------------------------------
# CSV 입출력
# --------------------------------------------------------------------------

_SAMPLE = (
    '"結果","日時","対象","ＩＰアドレス","ステータス","備考"\r\n'
    '"ＯＫ","2026-07-22 15:13:56","192.168.0.21","192.168.0.21","Time:     1ms",""\r\n'
    '"ＮＧ","2026-07-22 15:13:57","192.168.0.21","","Request timed out",""\r\n'
    '"ＮＧ","2026-07-22 15:13:58","192.168.0.21","192.168.43.1","Destination host unreachable",""\r\n'
)


def _write_sample(tmp_path, text=_SAMPLE, name="s.csv"):
    p = tmp_path / name
    p.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    return p


def test_read_csv_parses_rows_and_blanks(tmp_path):
    rows = ep.read_csv(_write_sample(tmp_path))
    assert len(rows) == 3
    assert rows[0] == (
        "ＯＫ",
        dt.datetime(2026, 7, 22, 15, 13, 56),
        "192.168.0.21",
        "192.168.0.21",
        "Time:     1ms",
        None,
    )
    assert rows[1][3] is None  # ＮＧ 행은 ＩＰアドレス 공란


def test_read_csv_preserves_unusual_status(tmp_path):
    """해석하지 않고 그대로 옮긴다 — 재구성으로는 만들 수 없는 값이다."""
    rows = ep.read_csv(_write_sample(tmp_path))
    assert rows[2][4] == "Destination host unreachable"
    assert rows[2][3] == "192.168.43.1"


def test_read_csv_rejects_wrong_header(tmp_path):
    bad = '"result","date","x","y","z","w"\r\n'
    with pytest.raises(ValueError, match="머리글"):
        ep.read_csv(_write_sample(tmp_path, bad))


def test_read_csv_rejects_short_row(tmp_path):
    text = _SAMPLE.rsplit('"ＮＧ"', 1)[0] + '"ＯＫ","2026-07-22 15:13:59","x"\r\n'
    with pytest.raises(ValueError, match="열 개수"):
        ep.read_csv(_write_sample(tmp_path, text))


def test_read_csv_rejects_bad_timestamp(tmp_path):
    text = (
        '"結果","日時","対象","ＩＰアドレス","ステータス","備考"\r\n'
        '"ＯＫ","어제","192.168.0.21","192.168.0.21","Time:     1ms",""\r\n'
    )
    with pytest.raises(ValueError, match="日時"):
        ep.read_csv(_write_sample(tmp_path, text))


def test_read_csv_rejects_empty_file(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_bytes(b"")
    with pytest.raises(ValueError, match="빈 파일"):
        ep.read_csv(p)


def test_write_csv_byte_format(tmp_path):
    """EXPING 이 뽑는 형식: UTF-8 BOM, CRLF, 전 필드 인용."""
    rows = ep.read_csv(_write_sample(tmp_path))
    out = tmp_path / "out.csv"
    ep.write_csv(out, rows)
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert raw.count(b"\r\n") == 4  # 머리글 + 3행
    assert b"\n" not in raw.replace(b"\r\n", b"")  # 홑 LF 없음
    body = raw.decode("utf-8-sig")
    assert all(line.startswith('"') and line.endswith('"') for line in body.splitlines())


def test_write_csv_roundtrip_is_stable(tmp_path):
    src = _write_sample(tmp_path)
    rows = ep.read_csv(src)
    out = tmp_path / "out.csv"
    ep.write_csv(out, rows)
    assert out.read_bytes() == src.read_bytes()
    assert ep.read_csv(out) == rows


# --------------------------------------------------------------------------
# tshark 출력 파싱
# --------------------------------------------------------------------------


def _tsv(*rows):
    return "".join("\t".join(str(c) for c in r) + "\n" for r in rows)


def test_parse_icmp_tsv_skips_malformed_lines():
    text = _tsv(
        (1.0, "10.0.0.1", "10.0.0.2", "8", "1", "5", ""),
        ("", "10.0.0.1", "10.0.0.2", "8", "1", "6"),  # 시각 없음
        ("bad", "10.0.0.1", "10.0.0.2", "8", "1", "7"),  # 시각 파싱 실패
        (2.0, "10.0.0.1"),  # 필드 부족
    )
    got = ep.parse_icmp_tsv(text)
    assert got == [(1.0, "10.0.0.1", "10.0.0.2", "8", "1", "5", "")]


def test_parse_icmp_line_guard_follows_field_list():
    """필드 수 가드는 TSHARK_FIELDS 에서 파생돼야 한다 — 개수를 하드코딩하면 깨진다.

    필드를 하나 늘렸을 때(wlan.fc.type 추가) 예전 폭의 줄이 들어오면 가드를 통과한 뒤
    인덱스 오류로 죽을 수 있다. 지금은 파생이라 조용히 None 이다.
    """
    short = "\t".join(["1.0"] + ["x"] * (len(ep.TSHARK_FIELDS) - 2)) + "\n"
    assert ep.parse_icmp_line(short) is None  # 한 칸 모자람 — epoch 는 유효하다
    long = "\t".join(["1.0"] + ["x"] * len(ep.TSHARK_FIELDS)) + "\n"
    assert ep.parse_icmp_line(long) is None  # 한 칸 넘침
    exact = "\t".join(["1.0"] + ["x"] * (len(ep.TSHARK_FIELDS) - 1)) + "\n"
    assert ep.parse_icmp_line(exact) is not None


def test_parse_icmp_line_returns_none_for_bad_input():
    assert ep.parse_icmp_line("1.0\ta\tb\t8\t1\t5\t\n") == (1.0, "a", "b", "8", "1", "5", "")
    assert ep.parse_icmp_line("1.0\ta\tb\n") is None  # 필드 부족
    assert ep.parse_icmp_line("x\ta\tb\t8\t1\t5\t\n") is None  # 시각 파싱 실패


def test_extract_exchanges_reports_tshark_failure():
    """tshark 가 비정상 종료하고 건진 프레임도 없으면 traceback 대신 ValueError."""
    with pytest.raises(ValueError, match="tshark 가 실패했다"):
        ep.extract_exchanges("/nonexistent.pcapng", tshark="/bin/false")


def test_extract_exchanges_warns_on_partial_capture(tmp_path, capsys):
    """프레임을 건졌어도 tshark 가 비정상 종료하면 조용히 넘기면 안 된다.

    잘린 캡처를 그대로 쓰면 못 읽은 요청만큼 손실률이 실제보다 낮게 나온다.
    """
    fake = tmp_path / "fake-tshark"
    fake.write_text(
        "#!/bin/sh\n"
        "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "echo 'tshark: The file appears to be damaged' >&2\n"
        "exit 2\n"
    )
    fake.chmod(0o755)

    exchanges, _ = ep.extract_exchanges("ignored.pcapng", tshark=str(fake))
    assert len(exchanges) == 1, "건진 프레임은 그대로 쓴다"
    err = capsys.readouterr().err
    assert "exit 2" in err
    assert "damaged" in err
    assert "낮게 나올 수 있으니" in err


def test_extract_exchanges_silent_when_tshark_succeeds(tmp_path, capsys):
    """정상 종료면 경고를 내지 않는다 — 늑대소년이 되면 안 된다."""
    fake = tmp_path / "ok-tshark"
    fake.write_text(
        "#!/bin/sh\n"
        "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    fake.chmod(0o755)
    ep.extract_exchanges("ignored.pcapng", tshark=str(fake))
    assert capsys.readouterr().err == ""


def _fake_tshark(tmp_path, body: str, name: str = "fake-tshark"):
    f = tmp_path / name
    f.write_text("#!/bin/sh\n" + body)
    f.chmod(0o755)
    return str(f)


# --------------------------------------------------------------------------
# 무선(802.11) 캡처 가드
# --------------------------------------------------------------------------

#: 유선 프레임 2개(요청+응답). 마지막 필드(wlan.fc.type)가 비어 있다.
_WIRED = (
    "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
    "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
)
#: 같은 교환이지만 802.11 헤더가 붙어 있다(wlan.fc.type=2).
_WIRELESS = (
    "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t2\\n'\n"
    "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t2\\n'\n"
)


def test_count_wireless_requests_counts_only_senders_requests():
    frames = [
        (1.0, "10.0.0.1", "10.0.0.2", "8", "7", "1", ""),
        (1.1, "10.0.0.1", "10.0.0.2", "8", "7", "2", "2"),  # 무선
        (1.2, "10.0.0.9", "10.0.0.2", "8", "7", "3", "2"),  # 남의 요청
        (1.3, "10.0.0.2", "10.0.0.1", "0", "7", "1", "2"),  # 응답은 안 센다
    ]
    assert ep.count_wireless_requests(frames, "10.0.0.1") == (2, 1)


def test_extract_exchanges_rejects_wireless_capture(tmp_path):
    """무선 캡처는 조용히 틀린 손실률을 내므로 막는다 (실측 0.16% 대 15.65%)."""
    with pytest.raises(ValueError, match="무선"):
        ep.extract_exchanges("x.pcapng", tshark=_fake_tshark(tmp_path, _WIRELESS))


def test_extract_exchanges_allows_wireless_when_asked(tmp_path):
    exchanges, sender = ep.extract_exchanges(
        "x.pcapng", tshark=_fake_tshark(tmp_path, _WIRELESS), allow_wireless=True
    )
    assert sender == "10.0.0.1" and len(exchanges) == 1


def test_extract_exchanges_warns_on_mixed_interface_capture(tmp_path, capsys):
    """유선+무선이 섞인 pcapng 는 같은 ping 이 두 번 세어진다 — 경고는 하되 막지는 않는다."""
    mixed = _fake_tshark(tmp_path, _WIRED + _WIRELESS.replace("\\t7\\t1\\t", "\\t7\\t2\\t"))
    exchanges, _ = ep.extract_exchanges("x.pcapng", tshark=mixed)
    assert len(exchanges) == 2
    err = capsys.readouterr().err
    assert "802.11" in err and "두 번 세어져" in err


def test_extract_exchanges_quiet_on_pure_wired(tmp_path, capsys):
    ep.extract_exchanges("x.pcapng", tshark=_fake_tshark(tmp_path, _WIRED))
    assert capsys.readouterr().err == ""


# --------------------------------------------------------------------------
# 자식 프로세스 상한 / 정리
# --------------------------------------------------------------------------


def test_extract_exchanges_kills_hung_tshark(tmp_path):
    """파이프 읽기에서 막히면 루프 안 검사로는 못 잡는다 — 밖에서 죽여야 한다."""
    hung = _fake_tshark(tmp_path, _WIRED + "exec sleep 300\n")  # exec: fd 를 쥔 손자를 남기지 않는다
    with pytest.raises(TimeoutError, match="끝나지 않아"):
        # 상한 자체를 검증하는 테스트라 값은 작을수록 좋다 (CI 시간).
        ep.extract_exchanges("x.pcapng", tshark=hung, child_timeout=0.3)


def test_extract_exchanges_kills_child_on_exception(tmp_path, monkeypatch):
    """중간에 예외가 나도 tshark 를 고아로 남기지 않는다 (pcap 핸들을 계속 쥔다)."""
    slow = _fake_tshark(tmp_path, _WIRED + "exec sleep 300\n")  # exec: fd 를 쥔 손자를 남기지 않는다

    def boom(line):
        raise RuntimeError("중단")

    # monkeypatch 는 테스트 종료 시 자동 복원된다 — 수동 되돌리기는 없어야 한다.
    monkeypatch.setattr(ep, "parse_icmp_line", boom)
    with pytest.raises(RuntimeError, match="중단"):
        ep.extract_exchanges("x.pcapng", tshark=slow, child_timeout=30.0)


def test_extract_exchanges_survives_huge_stderr(tmp_path):
    """stderr 를 파이프로 받으면 버퍼가 차는 순간 교착한다 — 임시 파일로 받아야 한다.

    경고가 쏟아지는 손상 캡처를 흉내낸다. 회귀하면 이 테스트는 끝나지 않는다.
    """
    fake = tmp_path / "fake-tshark"
    fake.write_text(
        "#!/bin/sh\n"
        # 파이프 버퍼(보통 64KB)를 훌쩍 넘기는 stderr 를 먼저 쏟는다.
        "awk 'BEGIN{for(i=0;i<20000;i++) print \"warn: malformed frame\" > \"/dev/stderr\"}'\n"
        "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
    )
    fake.chmod(0o755)

    exchanges, sender = ep.extract_exchanges("ignored.pcapng", tshark=str(fake))
    assert sender == "10.0.0.1"
    assert len(exchanges) == 1
    assert exchanges[0].rtt == pytest.approx(0.002)


def test_pick_sender_uses_request_majority():
    frames = [
        (1.0, "10.0.0.9", "10.0.0.2", "8", "1", "1", ""),
        (2.0, "10.0.0.1", "10.0.0.2", "8", "1", "2", ""),
        (3.0, "10.0.0.1", "10.0.0.2", "8", "1", "3", ""),
        (4.0, "10.0.0.2", "10.0.0.1", "0", "1", "3", ""),  # reply 는 세지 않는다
    ]
    assert ep.pick_sender(frames) == "10.0.0.1"


def test_pick_sender_raises_without_requests():
    with pytest.raises(ValueError, match="echo request"):
        ep.pick_sender([(1.0, "a", "b", "0", "1", "1", "")])


# --------------------------------------------------------------------------
# 요청/응답 짝짓기
# --------------------------------------------------------------------------


def test_pair_exchanges_matches_by_ident_seq_and_peer():
    frames = [
        (1.000, "10.0.0.1", "10.0.0.2", "8", "7", "1", ""),
        (1.002, "10.0.0.2", "10.0.0.1", "0", "7", "1", ""),
        (1.100, "10.0.0.1", "10.0.0.2", "8", "7", "2", ""),  # 응답 없음
    ]
    got = ep.pair_exchanges(frames, "10.0.0.1")
    assert len(got) == 2
    assert got[0].answered and got[0].rtt == pytest.approx(0.002)
    assert got[1].rtt is None


def test_pair_exchanges_ignores_reply_beyond_timeout():
    frames = [
        (1.0, "10.0.0.1", "10.0.0.2", "8", "7", "1", ""),
        (3.5, "10.0.0.2", "10.0.0.1", "0", "7", "1", ""),
    ]
    assert ep.pair_exchanges(frames, "10.0.0.1", timeout=1.0)[0].rtt is None
    assert ep.pair_exchanges(frames, "10.0.0.1", timeout=5.0)[0].rtt == pytest.approx(2.5)


def test_pair_exchanges_does_not_borrow_other_targets_reply():
    """같은 (ident, seq) 라도 상대 IP 가 다르면 남의 응답이다."""
    frames = [
        (1.0, "10.0.0.1", "10.0.0.2", "8", "7", "1", ""),
        (1.1, "10.0.0.3", "10.0.0.1", "0", "7", "1", ""),  # .3 이 보낸 응답
    ]
    assert ep.pair_exchanges(frames, "10.0.0.1")[0].rtt is None


def test_pair_exchanges_keeps_multi_target_time_order():
    """3대상 회전 로그의 순서는 대상별이 아니라 요청 시각 순이다."""
    frames = []
    t = 100.0
    for i in range(6):
        target = f"10.0.0.{21 + i % 3}"
        frames.append((t, "10.0.0.1", target, "8", "7", str(i), ""))
        frames.append((t + 0.001, target, "10.0.0.1", "0", "7", str(i), ""))
        t += 0.11
    got = ep.pair_exchanges(frames, "10.0.0.1")
    assert [e.target[-2:] for e in got] == ["21", "22", "23", "21", "22", "23"]
    assert [e.time for e in got] == sorted(e.time for e in got)


def test_pair_exchanges_ignores_requests_from_other_hosts():
    frames = [
        (1.0, "10.0.0.9", "10.0.0.2", "8", "7", "1", ""),
        (2.0, "10.0.0.1", "10.0.0.2", "8", "7", "2", ""),
    ]
    got = ep.pair_exchanges(frames, "10.0.0.1")
    assert len(got) == 1 and got[0].time == 2.0


def test_pair_exchanges_picks_earliest_reply_at_or_after_request():
    frames = [
        (5.0, "10.0.0.1", "10.0.0.2", "8", "7", "1", ""),
        (4.0, "10.0.0.2", "10.0.0.1", "0", "7", "1", ""),  # 요청보다 이르다 — 무시
        (5.3, "10.0.0.2", "10.0.0.1", "0", "7", "1", ""),
        (5.9, "10.0.0.2", "10.0.0.1", "0", "7", "1", ""),
    ]
    assert ep.pair_exchanges(frames, "10.0.0.1")[0].rtt == pytest.approx(0.3)


# --------------------------------------------------------------------------
# 꼬리 무응답 삭제
# --------------------------------------------------------------------------


def test_drop_trailing_unanswered_removes_only_the_tail():
    xs = [_ex(1.0), _ex(2.0, rtt=None), _ex(3.0), _ex(4.0, rtt=None), _ex(5.0, rtt=None)]
    kept, dropped = ep.drop_trailing_unanswered(xs)
    assert dropped == 2
    assert [e.time for e in kept] == [1.0, 2.0, 3.0]
    assert kept[1].rtt is None  # 중간 손실은 남긴다


def test_drop_trailing_unanswered_noop_when_last_is_answered():
    xs = [_ex(1.0, rtt=None), _ex(2.0)]
    kept, dropped = ep.drop_trailing_unanswered(xs)
    assert dropped == 0 and kept == xs


def test_drop_trailing_unanswered_can_empty_the_list():
    kept, dropped = ep.drop_trailing_unanswered([_ex(1.0, rtt=None)])
    assert kept == [] and dropped == 1


def test_drop_trailing_unanswered_does_not_mutate_input():
    xs = [_ex(1.0), _ex(2.0, rtt=None)]
    ep.drop_trailing_unanswered(xs)
    assert len(xs) == 2


# --------------------------------------------------------------------------
# 행 만들기
# --------------------------------------------------------------------------


def test_exchanges_to_rows_truncates_time_to_second():
    row = ep.exchanges_to_rows([_ex(1784700837.987654)])[0]
    assert row[1] == dt.datetime.fromtimestamp(1784700837.987654).replace(microsecond=0)
    assert row[1].microsecond == 0


def test_exchanges_to_rows_ng_row_has_no_ip():
    ok, ng = ep.exchanges_to_rows([_ex(1.0), _ex(2.0, rtt=None)])
    assert ok[0] == ep.RESULT_OK and ok[3] == "192.168.0.21"
    assert ng[0] == ep.RESULT_NG and ng[3] is None
    assert ng[4] == ep.STATUS_TIMEOUT
    assert ok[2] == ng[2] == "192.168.0.21"  # 対象 은 ＮＧ 행에도 남는다
    assert ok[5] is None and ng[5] is None  # 備考 는 항상 공란


def test_exchanges_to_rows_matches_csv_roundtrip(tmp_path):
    rows = ep.exchanges_to_rows([_ex(1784700837.1, rtt=0.0012), _ex(1784700837.3, rtt=None)])
    out = tmp_path / "r.csv"
    ep.write_csv(out, rows)
    body = list(csv.reader(io.StringIO(out.read_text(encoding="utf-8-sig"))))
    assert tuple(body[0]) == ep.HEADER
    assert body[1][0] == ep.RESULT_OK and body[1][4] == "Time:     1ms"
    assert body[2][0] == ep.RESULT_NG and body[2][3] == "" and body[2][4] == ep.STATUS_TIMEOUT


# --------------------------------------------------------------------------
# tshark 명령
# --------------------------------------------------------------------------


def test_build_tshark_cmd_filters_echo_only():
    cmd = ep.build_tshark_cmd("/x/y.pcapng", tshark="/usr/bin/tshark")
    assert cmd[:3] == ["/usr/bin/tshark", "-r", "/x/y.pcapng"]
    assert "icmp.type==8 || icmp.type==0" in cmd
    for field in ep.TSHARK_FIELDS:
        assert field in cmd
    assert cmd.count("-e") == len(ep.TSHARK_FIELDS)


# --------------------------------------------------------------------------
# XLSX (openpyxl 이 있을 때만)
# --------------------------------------------------------------------------


def test_write_xlsx_structure(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    rows = ep.exchanges_to_rows([_ex(1784700837.1), _ex(1784700837.3, rtt=None)])
    base = "FXA3000_RAIL_TEST1(1514_1534)"
    out = tmp_path / "w.xlsx"
    ep.write_xlsx(out, rows, base)

    wb = openpyxl.load_workbook(out)
    assert wb.sheetnames == list(ep.sheet_names(base))

    table_sheet, plain_sheet = wb.worksheets
    assert table_sheet.max_row == len(rows) + 1
    assert [c.value for c in table_sheet[1]] == list(ep.HEADER)
    assert table_sheet["B1"].number_format == ep.TABLE_SHEET_TIME_FORMAT, (
        "머리글 셀 B1 은 fill() 이 건너뛴다 — 별도 지정이 사라지면 기준 파일과 어긋난다"
    )
    assert table_sheet["B2"].number_format == ep.TABLE_SHEET_TIME_FORMAT
    assert plain_sheet["B2"].number_format == ep.PLAIN_SHEET_TIME_FORMAT
    assert [table_sheet.column_dimensions[c].width for c in "ABCDEF"] == list(ep.COLUMN_WIDTHS)
    assert table_sheet["A2"].font.name == ep.DEFAULT_FONT_NAME
    assert table_sheet["A2"].alignment.vertical == "center"
    assert table_sheet.sheet_format.defaultRowHeight == ep.DEFAULT_ROW_HEIGHT

    (table,) = table_sheet.tables.values()
    assert table.displayName == ep.table_name(base)
    assert table.ref == f"A1:F{len(rows) + 1}"
    assert table.tableStyleInfo.name == ep.TABLE_STYLE


def test_write_xlsx_values_match_rows_on_both_sheets(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    rows = ep.exchanges_to_rows([_ex(1784700837.1), _ex(1784700837.3, rtt=None)])
    out = tmp_path / "w.xlsx"
    ep.write_xlsx(out, rows, "base")
    wb = openpyxl.load_workbook(out)
    for ws in wb.worksheets:
        got = [tuple(r) for r in ws.iter_rows(min_row=2, values_only=True)]
        assert got == rows


def test_write_xlsx_copies_theme_from_reference(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    import zipfile

    ref = tmp_path / "ref.xlsx"
    openpyxl.Workbook().save(ref)
    with zipfile.ZipFile(ref) as z:
        want = z.read("xl/theme/theme1.xml")

    out = tmp_path / "w.xlsx"
    ep.write_xlsx(out, ep.exchanges_to_rows([_ex(1.0)]), "base", theme_from=ref)
    with zipfile.ZipFile(out) as z:
        assert z.read("xl/theme/theme1.xml") == want


def test_write_xlsx_survives_bad_theme_file(tmp_path, capsys):
    """--theme-from 이 xlsx 가 아니어도 중단하지 않고 기본 테마로 쓴다."""
    openpyxl = pytest.importorskip("openpyxl")
    bad = tmp_path / "not-a-workbook.xlsx"
    bad.write_text("이건 zip 이 아니다")
    out = tmp_path / "w.xlsx"
    ep.write_xlsx(out, ep.exchanges_to_rows([_ex(1.0)]), "base", theme_from=bad)
    assert "기본 테마로 진행" in capsys.readouterr().err
    assert openpyxl.load_workbook(out).worksheets[0].max_row == 2


def test_write_xlsx_survives_missing_theme_file(tmp_path, capsys):
    openpyxl = pytest.importorskip("openpyxl")
    out = tmp_path / "w.xlsx"
    ep.write_xlsx(out, ep.exchanges_to_rows([_ex(1.0)]), "base", theme_from=tmp_path / "nope.xlsx")
    assert "기본 테마로 진행" in capsys.readouterr().err
    assert openpyxl.load_workbook(out).worksheets[0].max_row == 2


def test_write_xlsx_accepts_rows_read_from_csv(tmp_path):
    """변환 경로(read_csv -> write_xlsx)도 같은 함수로 처리된다."""
    openpyxl = pytest.importorskip("openpyxl")
    rows = ep.read_csv(_write_sample(tmp_path))
    out = tmp_path / "conv.xlsx"
    ep.write_xlsx(out, rows, "conv")
    wb = openpyxl.load_workbook(out)
    got = [tuple(r) for r in wb.worksheets[0].iter_rows(min_row=2, values_only=True)]
    assert got == rows
