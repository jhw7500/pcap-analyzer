"""디버그 모드 프레임 테이블 row 직렬화 단위 테스트.

Frame -> 디버그 테이블 row 매핑이 정확히 8개 키
(number, timestamp, type_subtype, retry, mcs, rssi, reason_code, seq)를
올바른 값으로 노출하는지 검증한다. reason_code가 없으면 비어있음/None.
"""
from analyzer.web.frame_table import FRAME_ROW_KEYS, frame_to_row
from analyzer.web.evidence import build_debug_block
from tests.conftest import make_frame


EXPECTED_KEYS = {
    "number",
    "timestamp",
    "type_subtype",
    "retry",
    "mcs",
    "rssi",
    "reason_code",
    "seq",
}


class TestFrameToRow:
    def test_exactly_eight_keys(self):
        row = frame_to_row(make_frame())
        assert set(row.keys()) == EXPECTED_KEYS
        assert len(row) == 8

    def test_keys_constant_matches(self):
        assert set(FRAME_ROW_KEYS) == EXPECTED_KEYS

    def test_correct_values(self):
        f = make_frame(
            number=42,
            timestamp="2026-01-01 00:00:01.500",
            subtype="12",  # DeAuth -> Management
            retry=True,
            mcs="7",
            rssi="-60,-62",
            seq="100",
            reason_code="7",
        )
        row = frame_to_row(f)
        assert row["number"] == 42
        assert row["timestamp"] == "2026-01-01 00:00:01.500"
        assert row["type_subtype"] == "Management/DeAuth"
        assert row["retry"] is True
        assert row["mcs"] == 7
        assert row["rssi"] == -60
        assert row["seq"] == "100"
        assert row["reason_code"] == "7"

    def test_absent_reason_code_is_empty_or_none(self):
        # make_frame은 reason_code를 지정하지 않음 -> Frame 기본값("")
        row = frame_to_row(make_frame())
        assert row["reason_code"] in ("", None)

    def test_absent_mcs_and_rssi_are_none(self):
        row = frame_to_row(make_frame(mcs="", rssi=""))
        assert row["mcs"] is None
        assert row["rssi"] is None


class TestSourceBadge:
    def test_default_excludes_source(self):
        f = make_frame(source="w2")
        assert "source" not in frame_to_row(f)

    def test_include_source_adds_ninth_key(self):
        f = make_frame(source="w2")
        row = frame_to_row(f, include_source=True)
        assert set(row) == set(FRAME_ROW_KEYS) | {"source"}
        assert row["source"] == "w2"

    def test_debug_block_rows_carry_source_only_with_sniffer_compare(self):
        frames = [make_frame(number=1, source="w1"),
                  make_frame(number=2, epoch=1000.5, source="w2")]
        diag = {"diagnosis": {"issues": [{"frame_refs": [1, 2]}]}}

        multi = build_debug_block(
            {**diag, "sniffer_compare": {"tags": ["w1", "w2"]}},
            frames, index=None, roles=None)
        assert [r["source"] for r in multi["frames"]] == ["w1", "w2"]

        single = build_debug_block(dict(diag), frames, index=None, roles=None)
        assert all("source" not in r for r in single["frames"])
