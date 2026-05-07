"""reporter + log_merger 테스트."""
from analyzer.core.reporter import format_report
from analyzer.core.log_merger import merge_logs, _parse_log_line
from analyzer.core.models import AnalysisSection


class TestFormatReport:
    def test_basic(self):
        sections = [
            AnalysisSection(title="1. 개요", lines=["총 100프레임"], summary="100프레임"),
            AnalysisSection(title="2. Retry", lines=["Retry 10%"], summary="10%"),
        ]
        report = format_report(sections, "/tmp/test.pcap")
        assert "WLAN Pcap 종합 분석 리포트" in report
        assert "/tmp/test.pcap" in report
        assert "100프레임" in report

    def test_brief_mode(self):
        sections = [
            AnalysisSection(title="1. 개요", lines=["detail"], summary="summary"),
            AnalysisSection(title="종합 진단", lines=["WARNING"], summary="1 warning"),
        ]
        report = format_report(sections, "/tmp/t.pcap", brief=True)
        assert "간결 모드" in report
        # 진단 섹션은 brief에서도 전체 출력
        assert "WARNING" in report

    def test_wpa_used(self):
        report = format_report([], "/tmp/t.pcap", wpa_used=True)
        assert "사용" in report


class TestParseLogLine:
    def test_epoch_format(self):
        result = _parse_log_line("1704067200.123: wlan0: associated")
        assert result is not None
        assert result["format"] == "epoch"

    def test_syslog_format(self):
        result = _parse_log_line("Jan  1 12:00:00 host wpa_supplicant: connected")
        assert result is not None
        assert result["format"] == "syslog"

    def test_iso_format(self):
        result = _parse_log_line("2026-01-01 12:00:00 roaming started")
        assert result is not None
        assert result["format"] == "iso"

    def test_empty(self):
        assert _parse_log_line("") is None

    def test_no_match(self):
        assert _parse_log_line("random text without timestamp") is None


class TestMergeLogs:
    def test_no_files(self):
        sec = merge_logs([])
        assert "없음" in sec.summary

    def test_nonexistent_file(self):
        sec = merge_logs(["/nonexistent/path.log"])
        combined = "\n".join(sec.lines)
        assert "ERROR" in combined or "없음" in combined
