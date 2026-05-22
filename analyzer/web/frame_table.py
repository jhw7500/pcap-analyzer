"""디버그 모드 프레임 테이블 row 직렬화.

디버그 화면의 프레임 테이블은 타임라인(RSSI/retry/ping/roaming)과 양방향으로
동기화되는 표다. 표의 각 행은 하나의 Frame을 사람이 읽을 수 있는 고정된 컬럼
집합으로 환원한 것이며, 이 모듈이 그 단일 행 직렬화를 담당한다.

frame_refs(=stable tshark frame.number)로 finding의 근거 프레임을 표에서 바로
열 수 있도록, 행은 항상 frame.number를 포함한다.
"""
from typing import Any, Dict, Optional

from ..core.models import Frame

# 디버그 테이블이 노출하는 정확히 8개의 컬럼 키.
# (frame.number, timestamp, type/subtype, retry, MCS, RSSI, reason_code, seq)
FRAME_ROW_KEYS = (
    "number",
    "timestamp",
    "type_subtype",
    "retry",
    "mcs",
    "rssi",
    "reason_code",
    "seq",
)


def frame_to_row(frame: Frame) -> Dict[str, Any]:
    """Frame을 디버그 테이블 row(dict)로 직렬화한다.

    정확히 `FRAME_ROW_KEYS`의 8개 키만 노출한다:

    - ``number``: stable tshark frame.number (행/근거의 canonical id)
    - ``timestamp``: 사람이 읽는 시각 문자열
    - ``type_subtype``: "<type>/<subtype>" (예: "Management/DeAuth")
    - ``retry``: 802.11 retry 플래그(bool)
    - ``mcs``: 파싱된 MCS index(int) 또는 None
    - ``rssi``: 첫 안테나 RSSI(dBm, int) 또는 None
    - ``reason_code``: Deauth/Disassoc 사유 코드(str). 없으면 None.
    - ``seq``: 802.11 시퀀스 번호(str)
    """
    reason_code: Optional[str] = frame.reason_code or None
    return {
        "number": frame.number,
        "timestamp": frame.timestamp,
        "type_subtype": f"{frame.frame_type}/{frame.subtype_name}",
        "retry": frame.retry,
        "mcs": frame.mcs_int,
        "rssi": frame.rssi_first,
        "reason_code": reason_code,
        "seq": frame.seq,
    }
