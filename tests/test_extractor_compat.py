"""tshark 버전별 필드 호환성 단위 테스트."""
from unittest import mock
from analyzer.core import extractor


def test_supported_fields_parses_F_lines():
    """tshark -G fields 출력에서 F-prefixed 라인의 3번째 컬럼을 필드명으로 추출."""
    fake_output = (
        "F\tFrame Number\tframe.number\tFT_UINT32\t\n"
        "F\tFrame Time\tframe.time_epoch\tFT_DOUBLE\t\n"
        "F\t802.11ax MCS\tradiotap.he.data_3.data_mcs\tFT_UINT16\t\n"
    )
    with mock.patch.object(extractor.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = fake_output
        extractor._get_supported_fields.cache_clear()
        result = extractor._get_supported_fields("/usr/bin/tshark")
    assert "frame.number" in result
    assert "radiotap.he.data_3.data_mcs" in result
    assert "wlan_radio.11be.mcs" not in result


def test_filter_drops_unsupported():
    """4.2.2처럼 11be 필드 미지원 환경 — 자동 제외 + 인덱스 반환."""
    with mock.patch.object(extractor, "_get_supported_fields") as mock_get:
        mock_get.return_value = frozenset(extractor.TSHARK_FIELDS) - {"wlan_radio.11be.mcs"}
        used, dropped, indices = extractor._filter_unsupported_fields("/usr/bin/tshark")
    assert "wlan_radio.11be.mcs" not in used
    assert dropped == ["wlan_radio.11be.mcs"]
    expected_idx = extractor.TSHARK_FIELDS.index("wlan_radio.11be.mcs")
    assert indices == [expected_idx]


def test_filter_fallback_on_capability_failure():
    """capability detection 실패(empty set) 시 원본 그대로 사용 — 보수적."""
    with mock.patch.object(extractor, "_get_supported_fields") as mock_get:
        mock_get.return_value = frozenset()
        used, dropped, indices = extractor._filter_unsupported_fields("/usr/bin/tshark")
    assert used == list(extractor.TSHARK_FIELDS)
    assert dropped == []
    assert indices == []


def test_build_cmd_with_filtered_fields():
    """build_tshark_cmd가 fields 매개변수로 필드 리스트 override."""
    cmd = extractor.build_tshark_cmd(
        "/tmp/test.pcap",
        tshark_path="tshark",
        fields=["frame.number", "frame.time_epoch"],
    )
    assert "-e" in cmd
    e_args = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-e"]
    assert e_args == ["frame.number", "frame.time_epoch"]


def test_filter_keeps_column_alias_even_if_absent_in_supported():
    """_ws.col.* 필드는 tshark -G fields에 안 보여도 자동 supported."""
    # `_ws.col.Protocol`이 supported set에 없는 상황 시뮬레이션 (실제 tshark 동작 재현)
    supported_without_col = frozenset(extractor.TSHARK_FIELDS) - {"_ws.col.Protocol"}
    with mock.patch.object(extractor, "_get_supported_fields") as mock_get:
        mock_get.return_value = supported_without_col
        used, dropped, indices = extractor._filter_unsupported_fields("/usr/bin/tshark")
    # _ws.col.Protocol 은 자동 화이트리스트 → used에 포함, dropped에 안 들어감
    assert "_ws.col.Protocol" in used
    assert "_ws.col.Protocol" not in dropped
