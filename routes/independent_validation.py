"""웹 업로드 생명주기와 독립 로밍 검증기를 연결한다.

원본 업로드는 분석 직후 삭제되므로 검증도 같은 임시 파일 생명주기 안에서 실행한다.
패킷/STA 계산은 이 모듈이 아니라 analyzer import가 없는 standalone 구현이 담당한다.
"""

from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from scripts.roaming_independent_verify import VerificationCancelled, run_verification


class IndependentValidationCancelled(RuntimeError):
    """사용자가 독립 검증 실행 중 분석 job을 취소했다."""


def run_independent_web_validation(
    primary_path: str,
    wireless_paths: list[str],
    station_entries: list[dict[str, Any]],
    analyzer_result: dict[str, Any],
    *,
    tshark: str,
    source_names: list[str],
    progress_cb: Optional[Callable[[str, int], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> dict[str, Any]:
    """웹 입력을 standalone 검증 입력으로 변환하고 민감한 임시 경로를 제거한다."""
    paths = [primary_path, *wireless_paths]
    if len(source_names) != len(paths):
        raise ValueError("무선 원본 표시명 수와 캡처 수가 일치하지 않는다")
    sources: "OrderedDict[str, list[Path]]" = OrderedDict(
        (f"w{index}", [Path(path)]) for index, path in enumerate(paths, start=1)
    )
    station_paths: dict[str, Path] = {}
    for entry in station_entries:
        files = entry.get("files")
        if not isinstance(files, dict) or not files.get("wpa.log"):
            continue
        name = str(entry.get("name") or "station")
        if name in station_paths:
            raise ValueError(f"중복된 STA 로그 이름: {name}")
        station_paths[name] = Path(files["wpa.log"])

    def checked_progress(message: str, pct: int) -> None:
        if cancelled is not None and cancelled():
            raise IndependentValidationCancelled("독립 검증이 취소되었습니다.")
        if progress_cb is not None:
            progress_cb(message, pct)

    try:
        report = run_verification(
            sources,
            station_paths,
            analyzer_result=analyzer_result,
            reference="w1",
            tshark=tshark,
            progress_cb=checked_progress,
            cancelled=cancelled,
        )
    except VerificationCancelled as exc:
        raise IndependentValidationCancelled(str(exc)) from exc
    # /tmp 경로는 서버 내부 정보이며 업로드가 끝나면 무효다. 결과에는 사용자가
    # 알아볼 수 있는 원본 표시명만 남긴다.
    report["inputs"]["sources"] = {
        f"w{index}": [source_names[index - 1]] for index in range(1, len(paths) + 1)
    }
    report["inputs"]["stations"] = {name: f"{name}/wpa.log" for name in station_paths}
    for name, summary in report.get("station_logs", {}).get("by_station", {}).items():
        if isinstance(summary, dict):
            summary["path"] = f"{name}/wpa.log"
    report["status"] = "complete"
    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    report["mode"] = "web_upload_opt_in"
    return report


def failed_validation_payload(
    exc: Exception, temporary_paths: list[str]
) -> dict[str, Any]:
    """분석 성공은 보존하되 검증 실패를 구조화한다. 임시 경로는 노출하지 않는다."""
    message = str(exc) or exc.__class__.__name__
    for path in temporary_paths:
        if path:
            message = message.replace(path, "<업로드 파일>")
    return {
        "schema": "independent_roaming_verifier_v1",
        "status": "failed",
        "error": message,
        "independence": {"analyzer_imported": False},
        "mode": "web_upload_opt_in",
    }
