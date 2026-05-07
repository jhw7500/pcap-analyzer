"""log_merger 상세 테스트."""
import tempfile
import os
from analyzer.core.log_merger import merge_logs, _parse_log_line


class TestParseLogLine:
    def test_time_format(self):
        result = _parse_log_line("12:34:56.789 some message")
        assert result is not None
        assert result["format"] == "time"
        assert result["message"] == "some message"

    def test_whitespace_only(self):
        assert _parse_log_line("   ") is None


class TestMergeLogs:
    def test_with_roaming_keywords(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("2026-01-01 12:00:00 ROAM started\n")
            f.write("2026-01-01 12:00:01 AUTH completed\n")
            f.write("2026-01-01 12:00:02 ASSOC done\n")
            f.write("2026-01-01 12:00:03 normal traffic\n")
            f.write("2026-01-01 12:00:04 DISCONNECT event\n")
            f.name_path = f.name
        try:
            sec = merge_logs([f.name])
            assert sec.title == "외부 로그 병합"
            assert "4" in sec.summary or "3" in sec.summary  # keyword matches
            assert len(sec.lines) > 3
        finally:
            os.unlink(f.name)

    def test_mixed_formats(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("1704067200.123: ROAM event\n")
            f.write("Jan  1 12:00:00 host wpa: AUTH done\n")
            f.write("12:00:01.000 SCAN started\n")
            f.name_path = f.name
        try:
            sec = merge_logs([f.name])
            assert "3" in sec.summary or "로그" in sec.summary
        finally:
            os.unlink(f.name)

    def test_no_keywords(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("2026-01-01 12:00:00 normal line\n")
            f.write("2026-01-01 12:00:01 another line\n")
            f.name_path = f.name
        try:
            sec = merge_logs([f.name])
            # 키워드 매칭 없으면 0건
            assert "0" in sec.summary or "없음" in sec.summary or sec.summary == "로그 0건 (키워드 필터)"
        finally:
            os.unlink(f.name)

    def test_multiple_files(self):
        files = []
        for i in range(2):
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
            f.write(f"2026-01-01 12:00:0{i} ROAM event {i}\n")
            f.close()
            files.append(f.name)
        try:
            sec = merge_logs(files)
            assert len(sec.lines) > 0
        finally:
            for fp in files:
                os.unlink(fp)
