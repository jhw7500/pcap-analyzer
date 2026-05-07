"""에러 카탈로그 구조 테스트."""

from analyzer.errors import ErrorCode, ERROR_CATALOG, error_payload


class TestErrorCatalog:
    def test_all_codes_have_entry(self):
        for code in ErrorCode:
            assert code in ERROR_CATALOG, f"{code.value} missing in ERROR_CATALOG"

    def test_each_entry_has_message_and_hint(self):
        for code, entry in ERROR_CATALOG.items():
            assert "message" in entry, f"{code.value} has no message"
            assert "hint" in entry, f"{code.value} has no hint"
            assert isinstance(entry["message"], str)
            assert isinstance(entry["hint"], str)
            assert entry["message"], f"{code.value} message is empty"

    def test_code_values_are_upper_snake(self):
        for code in ErrorCode:
            assert code.value.isupper(), f"{code.value} not uppercase"
            assert " " not in code.value, f"{code.value} has spaces"

    def test_casefile_error_codes_exist(self):
        assert ErrorCode.INCIDENT_NOT_FOUND in ERROR_CATALOG
        assert ErrorCode.CASEFILE_UNAVAILABLE in ERROR_CATALOG


class TestErrorPayload:
    def test_has_three_fields(self):
        p = error_payload(ErrorCode.TSHARK_MISSING)
        assert set(p.keys()) == {"error", "code", "hint"}

    def test_code_field_matches_enum_value(self):
        p = error_payload(ErrorCode.INVALID_EXT)
        assert p["code"] == "INVALID_EXT"

    def test_extra_message_appended(self):
        p = error_payload(ErrorCode.FILE_TOO_LARGE, "(상한 200MB)")
        assert "(상한 200MB)" in p["error"]

    def test_extra_message_empty_unchanged(self):
        p = error_payload(ErrorCode.CANCELLED)
        assert p["error"] == ERROR_CATALOG[ErrorCode.CANCELLED]["message"]

    def test_casefile_payload_shape(self):
        p = error_payload(ErrorCode.INCIDENT_NOT_FOUND)
        assert set(p.keys()) == {"error", "code", "hint"}
