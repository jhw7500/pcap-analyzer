"""config 모듈 테스트."""
import json
import os
import tempfile
from unittest import mock

import config


class TestConfig:
    def test_get_default(self):
        # 환경변수나 파일에 없는 키는 default 반환
        val = config.get("nonexistent_key_12345", "fallback")
        assert val == "fallback"

    def test_get_from_env(self):
        with mock.patch.dict(os.environ, {"PCAP_TEST_KEY": "env_value"}):
            assert config.get("test_key") == "env_value"

    def test_ensure_data_dir(self):
        d = config.ensure_data_dir()
        assert d.exists()
        assert d.is_dir()

    def test_detect_tshark_returns_string_or_none(self):
        result = config.detect_tshark()
        assert result is None or isinstance(result, str)

    def test_max_upload_size(self):
        assert config.MAX_UPLOAD_SIZE == 200 * 1024 * 1024


class TestSafeAnalysisPath:
    def test_valid_id(self):
        path = config.safe_analysis_path("1234567890_sample_abcd1234")
        assert path is not None
        assert path.name == "1234567890_sample_abcd1234.json"
        assert path.parent == config.ensure_data_dir().resolve()

    def test_rejects_slash(self):
        assert config.safe_analysis_path("../etc/passwd") is None
        assert config.safe_analysis_path("foo/bar") is None

    def test_rejects_backslash(self):
        assert config.safe_analysis_path("..\\windows\\system32") is None

    def test_rejects_dotdot(self):
        assert config.safe_analysis_path("..") is None
        assert config.safe_analysis_path("foo..bar") is None

    def test_rejects_null_byte(self):
        assert config.safe_analysis_path("abc\0def") is None

    def test_rejects_empty(self):
        assert config.safe_analysis_path("") is None

    def test_rejects_absolute_path(self):
        # 상위 디렉토리로 escape 시도
        assert config.safe_analysis_path("/etc/passwd") is None
