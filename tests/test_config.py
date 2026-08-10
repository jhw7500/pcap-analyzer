"""config 모듈 테스트."""
import os
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
        # 2시간 무선 캡처 실측이 311MB라 구 기본값(200MB)으로는 업로드가 거부됐다.
        assert config.MAX_UPLOAD_SIZE == 1024 * 1024 * 1024

    def test_max_upload_size_accepts_two_hour_wireless_capture(self):
        # 실측 회귀 고정: 2시간 무선 모니터 캡처 311MB(143만 프레임)가 통과해야 한다.
        assert config.max_upload_size() >= 311 * 1024 * 1024


class TestMaskSecret:
    def test_empty(self):
        assert config.mask_secret("") == ""

    def test_short(self):
        assert config.mask_secret("abc") == "저장됨"

    def test_normal(self):
        result = config.mask_secret("sk-abc123def456xyz")
        # 마지막 5자만 노출 (56xyz)
        assert result.endswith("56xyz)")
        assert "sk-abc" not in result
        assert "456xyz" not in result  # 6자 tail 노출 금지
        assert result.startswith("저장됨")

    def test_exactly_8_chars(self):
        result = config.mask_secret("12345678")
        assert result == "저장됨 (****45678)"


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
