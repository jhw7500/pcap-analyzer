"""extractor 추가 테스트 — 정규화 함수, 엣지 케이스."""
from analyzer.core.extractor import _normalize_retry, _normalize_subtype, parse_tsv_line


class TestNormalizeRetry:
    def test_true_values(self):
        assert _normalize_retry("1") is True
        assert _normalize_retry("true") is True
        assert _normalize_retry("yes") is True
        assert _normalize_retry("1,1") is True  # 첫 번째 값만

    def test_false_values(self):
        assert _normalize_retry("0") is False
        assert _normalize_retry("false") is False
        assert _normalize_retry("") is False

    def test_comma_separated(self):
        assert _normalize_retry("0,1") is False  # 첫 번째 값만


class TestNormalizeSubtype:
    def test_hex(self):
        assert _normalize_subtype("0x0028") == "40"
        assert _normalize_subtype("0x0008") == "8"

    def test_decimal(self):
        assert _normalize_subtype("40") == "40"
        assert _normalize_subtype("8") == "8"

    def test_empty(self):
        assert _normalize_subtype("") == ""

    def test_comma_separated(self):
        assert _normalize_subtype("40,8") == "40"

    def test_invalid(self):
        result = _normalize_subtype("abc")
        assert result == "abc"


class TestParseTsvLineEdgeCases:
    def test_bssid_field(self):
        fields = ["1", "1000.0", "ts", "0", "40", "802.11", "100",
                  "7", "-60", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02",
                  "aa:bb:cc:00:00:03", "", "", "", "", "", "", "", ""]
        frame = parse_tsv_line("\t".join(fields))
        assert frame is not None
        assert frame.bssid == "aa:bb:cc:00:00:03"

    def test_icmp_seq_field(self):
        fields = ["1", "1000.0", "ts", "0", "40", "ICMP", "84",
                  "", "", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02",
                  "", "10.0.0.1", "10.0.0.2", "8", "", "", "", "100", "42"]
        frame = parse_tsv_line("\t".join(fields))
        assert frame is not None
        assert frame.icmp_seq == "42"
        assert frame.icmp_type == "8"

    def test_invalid_number(self):
        fields = ["bad", "1000.0", "ts", "0", "40", "802.11", "100",
                  "", "", "", "", "", "", "", "", "", "", "", "", ""]
        frame = parse_tsv_line("\t".join(fields))
        assert frame is None
