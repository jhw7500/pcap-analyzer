"""설정 관리 — JSON 파일 + 환경변수 폴백."""
import json
import os
import platform
import shutil
from pathlib import Path
from typing import Optional

CONFIG_PATH = Path(__file__).parent / "config.local.json"
DATA_DIR = Path(__file__).parent / "data" / "analyses"

# 업로드 크기 제한 (bytes) — max_upload_size()를 호출하는 게 권장
# 환경변수 PCAP_MAX_UPLOAD_MB 또는 config.local.json의 'max_upload_mb' 키로 오버라이드 가능.
#
# 기본 1GB: 실측 기준 2시간 무선 모니터 캡처가 311MB(143만 프레임, 200 fps)라
# 구 기본값 200MB로는 2시간짜리를 업로드 단계에서 거부했다. 유선 미러 캡처는
# 같은 2시간이 133MB로 훨씬 가볍다. 4시간대까지 여유를 두되 무한은 아니다 —
# 업로드는 임시 파일로 디스크에 한 벌 쓰이고 다중 무선은 파일별로 이 상한이
# 각각 적용되므로(최대 4개), 디스크 여유가 적은 호스트는 이 값을 낮춰 잡는다.
DEFAULT_MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1GB (기본)
MAX_UPLOAD_SIZE = DEFAULT_MAX_UPLOAD_SIZE  # 하위호환 (직접 참조 자제)


def _load_file() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
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
    CONFIG_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def get_all() -> dict:
    return _load_file()


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


#: 결과 JSON 옆에 두는 홈 화면용 경량 메타 사이드카의 접미사.
#: 본 결과(`{id}.json`)와 같은 디렉터리에 살지만 `*.json` 목록에서는 반드시
#: 걸러야 한다 — 그러지 않으면 사이드카 자체가 분석 결과로 잡힌다.
ANALYSIS_META_SUFFIX = ".meta.json"


def analysis_meta_path(analysis_id: str) -> Path:
    """분석 id에 대한 메타 사이드카 경로.

    홈 화면은 결과 목록에 id/pcap_name/frame_count/analyzed_at 4개 필드만 쓰는데,
    이걸 위해 결과 JSON 전체(2시간 캡처는 33MB)를 파싱하면 저장 건수에 비례해
    느려진다(실측 45건 847MB에서 8.6초). 저장 시점에 이 사이드카를 함께 써두고
    홈은 그것만 읽는다.

    경로 검증은 `safe_analysis_path`와 같은 규칙을 재사용한다 — 그 함수가 None을
    주는 id(경로 탈출 등)에는 사이드카 경로도 만들지 않는다.
    """
    base = safe_analysis_path(analysis_id)
    if base is None:
        raise ValueError(f"잘못된 분석 id: {analysis_id!r}")
    return base.with_suffix("").with_name(base.stem + ANALYSIS_META_SUFFIX)


def is_analysis_meta(path: Path) -> bool:
    """결과 목록 글롭에서 사이드카를 걸러내기 위한 판별."""
    return path.name.endswith(ANALYSIS_META_SUFFIX)


def max_upload_size() -> int:
    """업로드 상한 (bytes). 환경변수 → config.local.json → 기본값 순."""
    raw = get("max_upload_mb", "").strip()
    if raw:
        try:
            mb = int(raw)
            if mb > 0:
                return mb * 1024 * 1024
        except ValueError:
            pass
    return DEFAULT_MAX_UPLOAD_SIZE


def is_offline_assets() -> bool:
    """CDN 대신 static/vendor/의 로컬 에셋을 사용할지 여부.

    기본값 True (폐쇄망/오프라인 안전). 명시적으로 'false'로 지정한 경우에만
    CDN(online) 모드로 동작한다. (부재/빈값/그 외 값은 모두 offline)
    """
    return get("ui_offline_assets", "true").strip().lower() != "false"


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
