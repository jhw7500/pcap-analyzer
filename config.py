"""설정 관리 — JSON 파일 + 환경변수 폴백."""
import json
import os
import shutil
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.local.json"
DATA_DIR = Path(__file__).parent / "data" / "analyses"

# 업로드 크기 제한 (bytes)
MAX_UPLOAD_SIZE = 200 * 1024 * 1024  # 200MB


def _load_file() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def get(key: str, default: str = "") -> str:
    """환경변수 우선, 없으면 config 파일, 없으면 default."""
    env_key = f"PCAP_{key.upper()}"
    env_val = os.environ.get(env_key)
    if env_val is not None:
        return env_val
    return _load_file().get(key, default)


def set_value(key: str, value: str) -> None:
    data = _load_file()
    data[key] = value
    CONFIG_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def get_all() -> dict:
    return _load_file()


import platform
from typing import Optional

# Windows에서 Wireshark 기본 설치 경로
_WIN_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def detect_tshark() -> Optional[str]:
    """tshark 실행 경로를 찾는다. 없으면 None."""
    configured = get("tshark_path")
    if configured and shutil.which(configured):
        return configured
    found = shutil.which("tshark")
    if found:
        return found
    # Windows 기본 경로 폴백
    if platform.system() == "Windows":
        for p in _WIN_TSHARK_PATHS:
            if Path(p).exists():
                return p
    return None


def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def mask_secret(value: str) -> str:
    """민감값을 UI 노출용으로 마스킹. 빈 값이면 빈 문자열, 짧으면 '저장됨'만."""
    if not value:
        return ""
    if len(value) < 8:
        return "저장됨"
    return f"저장됨 (****{value[-5:]})"


def safe_analysis_path(analysis_id: str) -> Optional[Path]:
    """analysis_id에 대한 안전한 JSON 경로 반환. 유효하지 않으면 None.

    data/analyses 디렉토리 밖으로 탈출하는 id, 경로 구분자/상위 참조/널바이트
    포함 id는 모두 거부한다.
    """
    if not analysis_id:
        return None
    if any(ch in analysis_id for ch in ("/", "\\", "\0")):
        return None
    if ".." in analysis_id:
        return None
    data_dir = ensure_data_dir().resolve()
    candidate = (data_dir / f"{analysis_id}.json").resolve()
    try:
        candidate.relative_to(data_dir)
    except ValueError:
        return None
    return candidate
