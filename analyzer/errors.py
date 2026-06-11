"""에러 코드 카탈로그 — API 응답과 UI 안내의 단일 출처."""

from enum import Enum
from typing import Dict


class ErrorCode(str, Enum):
    TSHARK_MISSING = "TSHARK_MISSING"
    INVALID_EXT = "INVALID_EXT"
    INVALID_MAGIC = "INVALID_MAGIC"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    EMPTY_FILE = "EMPTY_FILE"
    NO_FRAMES = "NO_FRAMES"
    CANCELLED = "CANCELLED"
    ANALYSIS_NOT_FOUND = "ANALYSIS_NOT_FOUND"
    INVALID_ANALYSIS_ID = "INVALID_ANALYSIS_ID"
    INCIDENT_NOT_FOUND = "INCIDENT_NOT_FOUND"
    CASEFILE_UNAVAILABLE = "CASEFILE_UNAVAILABLE"
    AI_REVIEW_FAILED = "AI_REVIEW_FAILED"
    PDF_EXPORT_UNAVAILABLE = "PDF_EXPORT_UNAVAILABLE"
    PDF_RENDER_FAILED = "PDF_RENDER_FAILED"


ERROR_CATALOG: Dict[ErrorCode, Dict[str, str]] = {
    ErrorCode.TSHARK_MISSING: {
        "message": "tshark가 설치되어 있지 않습니다.",
        "hint": "apt install tshark (Debian/Ubuntu) 또는 brew install wireshark (macOS) 설치 후 /settings에서 경로를 지정하세요.",
    },
    ErrorCode.INVALID_EXT: {
        "message": "지원하지 않는 파일 형식입니다.",
        "hint": ".pcap, .pcapng, .cap 확장자만 업로드 가능합니다.",
    },
    ErrorCode.INVALID_MAGIC: {
        "message": "유효한 pcap/pcapng 포맷이 아닙니다.",
        "hint": "file 명령 또는 tshark -r 로 파일이 실제 pcap인지 먼저 확인하세요.",
    },
    ErrorCode.FILE_TOO_LARGE: {
        "message": "업로드 파일이 최대 크기를 초과했습니다.",
        "hint": "config.py의 MAX_UPLOAD_SIZE를 조정하거나 tshark로 사전 필터링 후 업로드하세요.",
    },
    ErrorCode.EMPTY_FILE: {
        "message": "빈 파일입니다.",
        "hint": "유효한 pcap 파일을 업로드하세요.",
    },
    ErrorCode.NO_FRAMES: {
        "message": "프레임을 추출하지 못했습니다.",
        "hint": "tshark 경로 또는 pcap 파일 상태를 확인하세요. 결과 JSON의 tshark_version으로 호환성을 점검하세요.",
    },
    ErrorCode.CANCELLED: {
        "message": "분석이 취소되었습니다.",
        "hint": "",
    },
    ErrorCode.ANALYSIS_NOT_FOUND: {
        "message": "분석 결과를 찾을 수 없습니다.",
        "hint": "분석 ID가 정확한지, data/analyses/에 JSON 파일이 존재하는지 확인하세요.",
    },
    ErrorCode.INVALID_ANALYSIS_ID: {
        "message": "잘못된 분석 ID입니다.",
        "hint": "경로 구분자나 상위 참조(..)가 포함된 ID는 차단됩니다.",
    },
    ErrorCode.INCIDENT_NOT_FOUND: {
        "message": "요청한 incident를 찾을 수 없습니다.",
        "hint": "incident_id를 확인하거나 기본 incident로 다시 요청하세요.",
    },
    ErrorCode.CASEFILE_UNAVAILABLE: {
        "message": "casefile을 생성할 수 없습니다.",
        "hint": "분석 JSON의 structured.ping 필드 유효성을 확인하세요.",
    },
    ErrorCode.AI_REVIEW_FAILED: {
        "message": "AI 리뷰 실행에 실패했습니다.",
        "hint": "API 키와 모델 설정을 확인하고 외부 네트워크 연결을 점검하세요.",
    },
    ErrorCode.PDF_EXPORT_UNAVAILABLE: {
        "message": "PDF 변환 엔진이 설치되어 있지 않습니다.",
        "hint": "pip install -r requirements-pdf.txt && playwright install chromium 으로 설치하세요(인터넷 필요). 오프라인 환경에서는 인쇄용 리포트(/analysis/{id}/report)를 열어 브라우저 인쇄(Ctrl+P)로 PDF 저장하세요.",
    },
    ErrorCode.PDF_RENDER_FAILED: {
        "message": "PDF 생성에 실패했습니다.",
        "hint": "playwright install chromium 으로 브라우저 설치를 확인하고, Linux 서버라면 fonts-noto-cjk 등 한글 폰트 설치를 점검하세요.",
    },
}


def error_payload(code: ErrorCode, extra_message: str = "") -> Dict[str, str]:
    """code/message/hint 3필드 응답 payload 생성."""
    entry = ERROR_CATALOG[code]
    msg = entry["message"]
    if extra_message:
        msg = f"{msg} {extra_message}"
    return {
        "error": msg,
        "code": code.value,
        "hint": entry["hint"],
    }
