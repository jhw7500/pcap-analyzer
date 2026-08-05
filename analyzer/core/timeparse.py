"""로컬 타임존 "YYYY-MM-DD HH:MM[:SS]" 시간 필터 문자열 → epoch 파싱.

무선 extractor.build_tshark_cmd의 `frame.time >= "..."` 필터도 tshark가 로컬
타임존으로 해석하므로, 이 파서도 로컬 타임존(datetime.timestamp())을 써야 두
필터가 같은 구간을 가리킨다. wired_ping.py(유선 ground truth)와
pipeline.py(다중 무선 시계 정렬 후 창 적용 — PR #23 리뷰 Finding A)가 같은
규칙을 공유해야 하므로 공개 헬퍼로 승격했다.
"""
import datetime as dt
from typing import Optional, Tuple

#: 시간 필터 입력 형식 — 초 생략형도 허용
TIME_FILTER_FORMATS: Tuple[str, ...] = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M")


def parse_local_epoch(value: str) -> Optional[float]:
    """"YYYY-MM-DD HH:MM[:SS]" 문자열을 로컬 타임존 기준 epoch로 파싱. 실패 시 None."""
    for fmt in TIME_FILTER_FORMATS:
        try:
            return dt.datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    return None
