"""분할 캡처 이어붙이기 — 스니퍼 파일 로테이션으로 쪼개진 **연속 캡처**를 하나로.

장시간 캡처는 스니퍼가 파일 크기/시간 단위로 로테이션해 `xxx_1.pcapng`,
`xxx_2.pcapng`, … 여러 조각으로 떨어진다(실측: 2시간 무선 캡처가 3조각).
이 조각들은 **시간이 겹치지 않는 같은 관측점의 연속 구간**이므로, 서로 다른
스니퍼가 같은 구간을 동시에 본 `merge.merge_captures`(TSF 시계 정렬 + 중복
제거 + 소스 비교)와는 성격이 정반대다 — 그쪽 경로로 보내면 겹치지도 않는
구간에 정렬·dedup을 시도하게 된다.

여기서는 pcap 레벨에서 mergecap으로 하나의 파일로 합친 뒤 파이프라인에
**단일 캡처로** 넘긴다. 그래서 분석 로직은 "원래 한 파일이었던 캡처"와
완전히 동일한 경로를 타고, frame.number도 합쳐진 파일 기준으로 일관되게
매겨진다(조각별로 1부터 다시 시작하는 번호가 섞이지 않는다).

mergecap은 기본적으로 **프레임 타임스탬프 기준 시간순 병합**이라 사용자가
조각을 순서대로 고르지 않아도 결과가 같다.
"""
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

#: mergecap 호출 상한(초). 실측 311MB(143만 프레임) 3조각 병합이 0.5초라
#: 넉넉하다 — 파일이 잠기거나 네트워크 마운트가 멈춘 경우의 안전장치.
MERGE_TIMEOUT_SEC = 900


def merge_split_captures(
    paths: List[str],
    out_path: str,
    mergecap_path: Optional[str] = None,
) -> Tuple[bool, str]:
    """조각 캡처들을 시간순으로 합쳐 out_path에 쓴다.

    Args:
        paths: 조각 파일 경로들 (2개 이상). 순서는 무관하다.
        out_path: 합쳐진 캡처를 쓸 경로.
        mergecap_path: mergecap 실행 경로. None이면 "mergecap".

    Returns:
        (성공 여부, 실패 사유). 성공이면 (True, ""), 실패면 (False, 사유).
        사유는 mergecap stderr의 마지막 줄들을 담아 원인이 그대로 보이게 한다
        (예: 서로 다른 encapsulation).
    """
    if len(paths) < 2:
        return False, "이어붙일 조각이 2개 미만이다"

    cmd = [mergecap_path or "mergecap", "-w", out_path, *paths]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=MERGE_TIMEOUT_SEC,
        )
    except FileNotFoundError:
        return False, "mergecap 실행 파일을 찾을 수 없다"
    except subprocess.TimeoutExpired:
        return False, f"mergecap이 {MERGE_TIMEOUT_SEC}초 안에 끝나지 않았다"
    except OSError as exc:
        return False, f"mergecap 실행 실패: {exc}"

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        tail = " / ".join(stderr.splitlines()[-3:]) if stderr else "(stderr 없음)"
        return False, f"mergecap exit {proc.returncode}: {tail}"

    # mergecap이 0을 반환해도 산출물이 없거나 비면 실패로 본다 — 빈 파일이
    # 그대로 파이프라인에 들어가면 "프레임 0건"이라는 엉뚱한 원인으로 표면화된다.
    out = Path(out_path)
    if not out.exists() or out.stat().st_size == 0:
        return False, "mergecap이 빈 결과를 만들었다"

    return True, ""


def merged_display_name(names: List[str]) -> str:
    """합쳐진 캡처의 표시 이름 — "첫조각.pcapng 외 N개 (이어붙임)".

    UI/리포트에서 이 결과가 여러 조각을 합친 것임을 숨기지 않기 위한 이름이다
    (정직한 표기 — 조각 수를 그대로 노출한다).
    """
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return f"{names[0]} 외 {len(names) - 1}개 (이어붙임)"
