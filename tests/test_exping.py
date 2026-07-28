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
        (1.0, "10.0.0.1", "10.0.0.2", "8", "1", "5"),
        ("", "10.0.0.1", "10.0.0.2", "8", "1", "6"),  # 시각 없음
        ("bad", "10.0.0.1", "10.0.0.2", "8", "1", "7"),  # 시각 파싱 실패
        (2.0, "10.0.0.1"),  # 필드 부족
    )
    got = ep.parse_icmp_tsv(text)
    assert got == [(1.0, "10.0.0.1", "10.0.0.2", "8", "1", "5")]


def test_parse_icmp_line_returns_none_for_bad_input():
    assert ep.parse_icmp_line("1.0\ta\tb\t8\t1\t5\n") == (1.0, "a", "b", "8", "1", "5")
    assert ep.parse_icmp_line("1.0\ta\tb\n") is None  # 필드 부족
    assert ep.parse_icmp_line("x\ta\tb\t8\t1\t5\n") is None  # 시각 파싱 실패


def test_extract_exchanges_reports_tshark_failure():
    """tshark 가 비정상 종료하고 건진 프레임도 없으면 traceback 대신 ValueError."""
    with pytest.raises(ValueError, match="tshark 가 실패했다"):
        ep.extract_exchanges("/nonexistent.pcapng", tshark="/bin/false")


def test_pick_sender_uses_request_majority():
    frames = [
        (1.0, "10.0.0.9", "10.0.0.2", "8", "1", "1"),
        (2.0, "10.0.0.1", "10.0.0.2", "8", "1", "2"),
        (3.0, "10.0.0.1", "10.0.0.2", "8", "1", "3"),
        (4.0, "10.0.0.2", "10.0.0.1", "0", "1", "3"),  # reply 는 세지 않는다
    ]
    assert ep.pick_sender(frames) == "10.0.0.1"


def test_pick_sender_raises_without_requests():
    with pytest.raises(ValueError, match="echo request"):
        ep.pick_sender([(1.0, "a", "b", "0", "1", "1")])


# --------------------------------------------------------------------------
# 요청/응답 짝짓기
# --------------------------------------------------------------------------


def test_pair_exchanges_matches_by_ident_seq_and_peer():
    frames = [
        (1.000, "10.0.0.1", "10.0.0.2", "8", "7", "1"),
        (1.002, "10.0.0.2", "10.0.0.1", "0", "7", "1"),
        (1.100, "10.0.0.1", "10.0.0.2", "8", "7", "2"),  # 응답 없음
    ]
    got = ep.pair_exchanges(frames, "10.0.0.1")
    assert len(got) == 2
    assert got[0].answered and got[0].rtt == pytest.approx(0.002)
    assert got[1].rtt is None


def test_pair_exchanges_ignores_reply_beyond_timeout():
    frames = [
        (1.0, "10.0.0.1", "10.0.0.2", "8", "7", "1"),
        (3.5, "10.0.0.2", "10.0.0.1", "0", "7", "1"),
    ]
    assert ep.pair_exchanges(frames, "10.0.0.1", timeout=1.0)[0].rtt is None
    assert ep.pair_exchanges(frames, "10.0.0.1", timeout=5.0)[0].rtt == pytest.approx(2.5)


def test_pair_exchanges_does_not_borrow_other_targets_reply():
    """같은 (ident, seq) 라도 상대 IP 가 다르면 남의 응답이다."""
    frames = [
        (1.0, "10.0.0.1", "10.0.0.2", "8", "7", "1"),
        (1.1, "10.0.0.3", "10.0.0.1", "0", "7", "1"),  # .3 이 보낸 응답
    ]
    assert ep.pair_exchanges(frames, "10.0.0.1")[0].rtt is None


def test_pair_exchanges_keeps_multi_target_time_order():
    """3대상 회전 로그의 순서는 대상별이 아니라 요청 시각 순이다."""
    frames = []
    t = 100.0
    for i in range(6):
        target = f"10.0.0.{21 + i % 3}"
        frames.append((t, "10.0.0.1", target, "8", "7", str(i)))
        frames.append((t + 0.001, target, "10.0.0.1", "0", "7", str(i)))
        t += 0.11
    got = ep.pair_exchanges(frames, "10.0.0.1")
    assert [e.target[-2:] for e in got] == ["21", "22", "23", "21", "22", "23"]
    assert [e.time for e in got] == sorted(e.time for e in got)


def test_pair_exchanges_ignores_requests_from_other_hosts():
    frames = [
        (1.0, "10.0.0.9", "10.0.0.2", "8", "7", "1"),
        (2.0, "10.0.0.1", "10.0.0.2", "8", "7", "2"),
    ]
    got = ep.pair_exchanges(frames, "10.0.0.1")
    assert len(got) == 1 and got[0].time == 2.0


def test_pair_exchanges_picks_earliest_reply_at_or_after_request():
    frames = [
        (5.0, "10.0.0.1", "10.0.0.2", "8", "7", "1"),
        (4.0, "10.0.0.2", "10.0.0.1", "0", "7", "1"),  # 요청보다 이르다 — 무시
        (5.3, "10.0.0.2", "10.0.0.1", "0", "7", "1"),
        (5.9, "10.0.0.2", "10.0.0.1", "0", "7", "1"),
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
