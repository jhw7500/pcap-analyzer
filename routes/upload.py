"""pcap 업로드 + 분석 실행 + 취소 + 진행률 polling (job id 기반)."""
import asyncio
import json
import tempfile
import threading
import time
import uuid
from functools import partial
from pathlib import Path
from typing import List

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import config
from analyzer.core.pcap_magic import has_valid_pcap_magic
from analyzer.errors import ErrorCode, error_payload
from analyzer.core.split_merge import merge_split_captures, merged_display_name
from analyzer.core.station_log import STATION_LOG_FILES
from analyzer.pipeline import run_analysis

_UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1MB
_JOBS_MAX = 100  # 최근 N개만 유지
_MAX_WIRELESS_FILES = 4  # 무선 **캡처(관측점)** 수: 기본(file) 1개 + wireless_files 최대 3개
#: 한 캡처를 이루는 분할 조각 수 상한. 조각마다 max_upload_size가 따로
#: 적용되므로 이 값은 디스크 폭주를 막는 상한이다(2시간 무선 캡처가 실측 3조각).
_MAX_SPLIT_PARTS = 32
#: STA 로그 세트 상한 — 호기(STA) 수 × 파일 3개. 넉넉히 잡되 무제한은 아니다.
_MAX_STATION_LOG_FILES = 60
#: STA 로그 1개 파일 상한(bytes). 실측 wpa/kern/logger 각 0.4~0.6MB.
_MAX_STATION_LOG_BYTES = 64 * 1024 * 1024
#: 요청 하나가 임시 파일로 쓸 수 있는 **합계** 상한(bytes).
#: 파일별 상한(max_upload_size)만 두면 관측점 5개(주 캡처·유선·추가 무선 3) ×
#: 분할 조각 32개 × 1GB = 이론상 160GB가 한 요청에 들어온다. 실측 2시간 무선
#: 3조각이 311MB, 유선 133MB라 8GB면 4시간대 다중 스니퍼도 넉넉하고 디스크
#: 여유가 적은 호스트를 지켜준다.
_MAX_REQUEST_TOTAL_BYTES = 8 * 1024 * 1024 * 1024


class _UploadBudget:
    """한 요청이 임시 파일로 쓴 누적 바이트 — **파일 경계를 넘어** 합산한다.

    개별 파일 상한은 파일 하나가 디스크를 삼키는 것만 막는다. 조각·다중 스니퍼로
    파일 수가 늘어나는 경로에서는 합계를 봐야 한다.
    """
    __slots__ = ("used", "limit")

    def __init__(self, limit=None) -> None:
        # 기본값을 시그니처에 박으면 def 시점에 고정돼 테스트에서 상한을 낮출 수
        # 없다 — 호출 시점에 모듈 상수를 읽는다.
        self.used = 0
        self.limit = _MAX_REQUEST_TOTAL_BYTES if limit is None else limit

    def add(self, n: int) -> bool:
        """n바이트를 더한다. 상한을 넘으면 False."""
        self.used += n
        return self.used <= self.limit

    @property
    def limit_gb(self) -> float:
        return round(self.limit / (1024 ** 3), 1)


router = APIRouter()
templates = Jinja2Templates(directory="templates")

# job_id → {msg, pct, active, created, cancel, tmp}
_jobs: dict = {}
_jobs_lock = threading.Lock()


def _sanitize_job_id(raw: str) -> str:
    """클라이언트 제공 job_id 검증 — 영숫자/하이픈/언더스코어, 8~64자만 허용.

    클라이언트가 분석 시작 전 미리 job_id를 만들어 보내면(진행률/취소를 본인
    job에만 한정하기 위함) 그대로 _jobs 키로 쓰이므로, 형식을 제한해 비정상
    입력을 막는다. 부적합하면 빈 문자열 → 호출 측이 서버 uuid로 대체.
    """
    raw = (raw or "").strip()
    if not (8 <= len(raw) <= 64):
        return ""
    if not all(c.isalnum() or c in "-_" for c in raw):
        return ""
    return raw


def _set_progress(job_id: str, msg: str, pct: int, active: bool = True) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["msg"] = msg
        job["pct"] = pct
        job["active"] = active


def _prune_jobs_locked() -> None:
    """종료된 오래된 job을 최근 N개만 남기고 정리. 호출 전 _jobs_lock 점유 필요."""
    if len(_jobs) <= _JOBS_MAX:
        return
    finished = sorted(
        ((jid, j) for jid, j in _jobs.items() if not j["active"]),
        key=lambda x: x[1]["created"],
    )
    to_remove = len(_jobs) - _JOBS_MAX
    for jid, _ in finished[:to_remove]:
        _jobs.pop(jid, None)


#: 홈 목록 카드에 쓰는 필드 — 사이드카에 담기는 것도 정확히 이 4개다.
_META_FIELDS = ("id", "pcap_name", "frame_count", "analyzed_at")


def write_analysis_meta(analysis_id: str, result: dict) -> None:
    """결과 저장 직후 홈 화면용 경량 메타 사이드카를 쓴다.

    실패해도 분석 자체는 성공이므로 조용히 넘어간다 — 사이드카가 없으면
    `index()`가 본 파일을 파싱하는 폴백 경로를 타고 그때 다시 만든다.
    """
    try:
        meta = {k: result.get(k) for k in _META_FIELDS}
        meta["id"] = meta.get("id") or analysis_id
        config.analysis_meta_path(analysis_id).write_text(
            json.dumps(meta, ensure_ascii=False, default=str), encoding="utf-8"
        )
    except (OSError, ValueError, TypeError):
        pass


def _analysis_card(result_path: Path) -> dict:
    """결과 파일 하나에 대한 홈 목록 카드.

    사이드카가 있으면 그것만 읽는다(수백 바이트). 없으면(구버전 결과) 본 파일을
    한 번 파싱해 카드를 만들고 사이드카를 새로 써 다음부터는 빠른 경로를 탄다 —
    2시간 캡처 결과는 33MB라 매 홈 로드에서 이걸 파싱하면 저장 건수에 비례해
    느려진다(실측 45건 847MB에서 8.6초).
    """
    analysis_id = result_path.stem
    try:
        meta_path = config.analysis_meta_path(analysis_id)
    except ValueError:
        meta_path = None
    if meta_path is not None and meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            return {
                "id": meta.get("id") or analysis_id,
                "pcap_name": meta.get("pcap_name") or "?",
                "frame_count": meta.get("frame_count") or 0,
                "analyzed_at": meta.get("analyzed_at") or "?",
            }
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            pass   # 손상된 사이드카는 아래 본 파일 파싱으로 복구
    try:
        full = json.loads(result_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError, MemoryError):
        # 호출부(index)도 앞의 세 가지는 잡지만 MemoryError는 통과시킨다 —
        # 결과 하나가 33MB라 여유가 빠듯한 호스트에서 홈 화면 전체가 죽을 수 있다.
        # 카드 하나를 물음표로 두는 편이 목록을 통째로 잃는 것보다 낫다.
        return {"id": analysis_id, "pcap_name": "?",
                "frame_count": 0, "analyzed_at": "?"}
    write_analysis_meta(analysis_id, full)
    return {
        "id": full.get("id", analysis_id),
        "pcap_name": full.get("pcap_name", "?"),
        "frame_count": full.get("frame_count", 0),
        "analyzed_at": full.get("analyzed_at", "?"),
    }


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    """홈 화면.

    `async def`가 아니라 `def`인 게 의도적이다 — 파일 I/O와 (폴백 시) json 파싱은
    동기 blocking이라 이벤트 루프에서 돌리면 그동안 서버 전체가 멈춘다. 특히
    json.loads는 GIL을 놓지 않아 같은 프로세스 threadpool에서 진행 중인 분석까지
    굶긴다. FastAPI는 `def` 엔드포인트를 threadpool로 내보낸다.
    """
    tshark = config.detect_tshark()
    data_dir = config.ensure_data_dir()
    analyses = []
    for f in sorted(data_dir.glob("*.json"), reverse=True):
        if config.is_analysis_meta(f):
            continue        # 사이드카는 분석 결과가 아니다
        try:
            analyses.append(_analysis_card(f))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue
    return templates.TemplateResponse(request, "index.html", {
        "tshark": tshark,
        "analyses": analyses,
        "offline_assets": config.is_offline_assets(),
        "max_upload_mb": config.max_upload_size() // (1024 * 1024),
    })


@router.get("/api/progress/{job_id}")
async def get_progress_by_id(job_id: str):
    """특정 job의 진행률."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return JSONResponse({"error": "job not found"}, status_code=404)
        return JSONResponse({
            "msg": job["msg"],
            "pct": job["pct"],
            "active": job["active"],
        })


@router.get("/api/progress")
async def get_progress_latest():
    """가장 최근 active job의 진행률. active 없으면 idle 0% (이전 finished 표시 안 함)."""
    with _jobs_lock:
        active = [j for j in _jobs.values() if j["active"]]
        if not active:
            return JSONResponse({"msg": "", "pct": 0, "active": False})
        target = max(active, key=lambda j: j["created"])
        return JSONResponse({
            "msg": target["msg"],
            "pct": target["pct"],
            "active": target["active"],
        })


async def _save_pcap_upload(file: UploadFile, budget=None):
    """업로드 파일 검증·임시 저장. 반환 (tmp_path, error_response) — 하나만 non-None.

    계약(PR #23 리뷰 8라운드 Finding B — 호출부가 재확인할 필요 없도록 명시):
    에러 응답(두 번째 원소가 non-None)으로 반환할 때는 **이 함수가 자신이
    만든 tmp를 이미 정리(unlink)한 뒤**다 — 그 경로는 첫 번째 원소로 항상
    `None`을 반환하므로 호출부가 그 tmp를 별도로 지울 필요가 없다(지우려
    해도 `None`이라 지울 대상이 없다).
    """
    name = file.filename or "unknown.pcap"
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        return None, JSONResponse(error_payload(ErrorCode.INVALID_EXT), status_code=400)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(name).suffix)
    total = 0
    first_chunk = True
    try:
        while True:
            chunk = await file.read(_UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            if first_chunk:
                if not has_valid_pcap_magic(chunk):
                    tmp.close()
                    Path(tmp.name).unlink(missing_ok=True)
                    return None, JSONResponse(
                        error_payload(ErrorCode.INVALID_MAGIC), status_code=400)
                first_chunk = False
            total += len(chunk)
            if total > config.max_upload_size():
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
                limit_mb = config.max_upload_size() // (1024 * 1024)
                return None, JSONResponse(
                    error_payload(ErrorCode.FILE_TOO_LARGE, f"(상한 {limit_mb}MB)"),
                    status_code=413)
            if budget is not None and not budget.add(len(chunk)):
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
                return None, JSONResponse(
                    error_payload(
                        ErrorCode.FILE_TOO_LARGE,
                        f"(요청 합계 상한 {budget.limit_gb}GB — 조각·다중 스니퍼 합산)",
                    ),
                    status_code=413)
            tmp.write(chunk)
    except Exception:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
        raise
    tmp.close()
    if first_chunk:
        Path(tmp.name).unlink(missing_ok=True)
        return None, JSONResponse(error_payload(ErrorCode.EMPTY_FILE), status_code=400)
    return tmp.name, None


async def _save_capture_group(files: List[UploadFile], budget=None):
    """한 캡처를 이루는 파일들(분할 조각 1개 이상)을 저장하고 단일 경로로 만든다.

    반환 `(tmp_path, names, error_response)` — error가 non-None이면 tmp_path는
    None이고 이 함수가 자기가 만든 임시 파일을 **모두 정리한 뒤**다
    (`_save_pcap_upload`의 계약을 그룹 단위로 확장).

    조각이 1개면 기존 단일 업로드와 **완전히 동일한 경로**(mergecap 미호출)를
    타서 동작이 바뀌지 않는다. 2개 이상이면 mergecap으로 시간순 병합해 하나의
    캡처로 만든다 — 조각들은 같은 관측점의 연속 구간이라 다중 스니퍼 병합
    (TSF 정렬 + dedup)과는 다른 처리가 필요하다(analyzer/core/split_merge 참조).
    """
    if len(files) > _MAX_SPLIT_PARTS:
        return None, [], JSONResponse(
            error_payload(
                ErrorCode.TOO_MANY_FILES,
                f"(한 캡처의 분할 조각은 최대 {_MAX_SPLIT_PARTS}개)",
            ),
            status_code=400,
        )
    tmps: List[str] = []
    names: List[str] = []
    for f in files:
        tmp, err = await _save_pcap_upload(f, budget)
        if err is not None:
            _cleanup_tmps(*tmps)
            return None, [], err
        tmps.append(tmp)
        names.append(f.filename or "unknown.pcap")

    if not tmps:
        return None, [], JSONResponse(
            error_payload(ErrorCode.EMPTY_FILE), status_code=400)
    if len(tmps) == 1:
        return tmps[0], names, None

    mergecap = config.detect_mergecap()
    if not mergecap:
        _cleanup_tmps(*tmps)
        return None, [], JSONResponse(
            error_payload(ErrorCode.MERGECAP_MISSING), status_code=500)

    merged = tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng")
    merged.close()
    # mergecap은 블로킹 subprocess다 — async 핸들러에서 직접 부르면 병합이 끝날
    # 때까지 **이벤트 루프 전체가 멈춰** 진행률 폴링·취소·다른 요청이 모두 막힌다
    # (홈 `index()`를 `def`로 내린 것과 같은 이유이고, 분석 본체가 executor로
    # 나가 있는 것과도 일관된다). 실측 311MB는 0.5초지만 느린 파일시스템이나
    # 타임아웃(MERGE_TIMEOUT_SEC)에 걸리면 그만큼 서버가 서지 못한다.
    loop = asyncio.get_running_loop()
    ok, reason = await loop.run_in_executor(
        None, partial(merge_split_captures, tmps, merged.name, mergecap_path=mergecap)
    )
    # 조각들은 병합 성공·실패와 무관하게 더 이상 필요 없다.
    _cleanup_tmps(*tmps)
    if not ok:
        _cleanup_tmps(merged.name)
        return None, [], JSONResponse(
            error_payload(ErrorCode.MERGE_FAILED, f"({reason})"), status_code=400)
    return merged.name, names, None


def _cleanup_tmps(*paths: str) -> None:
    """주어진 임시 경로들을 모두 unlink 시도(존재하지 않아도 무시). 빈 문자열은 skip.

    경로 하나의 unlink가 raise(예: Windows에서 백신/인덱서가 파일을 잠금)해도
    나머지 경로는 계속 정리한다 — try/except 없이 순회하면 첫 실패에서 예외가
    전파돼 그 뒤 경로들이 전부 누수된다(PR #23 리뷰 2라운드 Finding C).
    missing_ok=True는 "이미 없는 파일"만 안전하게 무시할 뿐 "존재하는데
    잠긴 파일"의 OSError는 그대로 던지므로 이 함수가 자체 흡수한다 —
    호출부가 다시 try/except로 감쌀 필요가 없다(감싸면 절대 실행되지
    않는 except 블록만 남는다, PR #23 리뷰 7라운드 Finding B).
    """
    for p in paths:
        if not p:
            continue
        try:
            Path(p).unlink(missing_ok=True)
        except OSError:
            pass


async def _save_station_logs(files: List[UploadFile], budget=None):
    """호기별 STA 로그 세트를 임시 저장하고 파이프라인 입력 형태로 만든다.

    브라우저 디렉터리 업로드는 파일명만 보내므로, 클라이언트가 FormData의 filename
    자리에 `webkitRelativePath`(예: ``1호기/wpa.log``)를 넣어 보낸다. 여기서 그
    **디렉터리 부분을 호기 이름으로** 쓰고 basename으로 로그 종류를 판별한다.

    반환 `(entries, tmp_paths, error)` — entries는
    ``[{"name": "1호기", "files": {"wpa.log": 경로, ...}}, ...]``.
    STATION_LOG_FILES에 없는 파일은 **조용히 무시**한다(폴더째 올리면 cpu/stat 등
    관심 없는 로그가 대량으로 딸려온다).
    """
    if len(files) > _MAX_STATION_LOG_FILES:
        return None, [], JSONResponse(
            error_payload(
                ErrorCode.TOO_MANY_FILES,
                f"(STA 로그는 최대 {_MAX_STATION_LOG_FILES}개)",
            ),
            status_code=400,
        )
    grouped: dict = {}
    tmps: List[str] = []
    for f in files:
        raw = (f.filename or "").replace("\\", "/")
        if not raw:
            continue
        parts = [p for p in raw.split("/") if p not in ("", ".", "..")]
        if not parts:
            continue
        base = parts[-1]
        if base not in STATION_LOG_FILES:
            continue        # 관심 없는 로그(cpu/stat/...)는 무시
        station = parts[-2] if len(parts) >= 2 else "station"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"-{base}")
        total = 0
        try:
            while True:
                chunk = await f.read(_UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if budget is not None and not budget.add(len(chunk)):
                    tmp.close()
                    _cleanup_tmps(tmp.name, *tmps)
                    return None, [], JSONResponse(
                        error_payload(
                            ErrorCode.FILE_TOO_LARGE,
                            f"(요청 합계 상한 {budget.limit_gb}GB)",
                        ),
                        status_code=413,
                    )
                if total > _MAX_STATION_LOG_BYTES:
                    tmp.close()
                    _cleanup_tmps(tmp.name, *tmps)
                    limit_mb = _MAX_STATION_LOG_BYTES // (1024 * 1024)
                    return None, [], JSONResponse(
                        error_payload(
                            ErrorCode.FILE_TOO_LARGE,
                            f"(STA 로그 {base} — 상한 {limit_mb}MB)",
                        ),
                        status_code=413,
                    )
                tmp.write(chunk)
        except Exception:
            tmp.close()
            _cleanup_tmps(tmp.name, *tmps)
            raise
        tmp.close()
        if total == 0:
            Path(tmp.name).unlink(missing_ok=True)
            continue
        tmps.append(tmp.name)
        grouped.setdefault(station, {})[base] = tmp.name

    entries = [{"name": k, "files": v} for k, v in sorted(grouped.items())]
    return entries, tmps, None


@router.post("/api/upload")
async def upload_pcap(
    # file / wired_file 은 **하나의 캡처를 이루는 분할 조각들**을 받는다(1개면
    # 기존과 동일). 스니퍼 파일 로테이션으로 쪼개진 연속 캡처를 mergecap으로
    # 이어붙여 단일 캡처로 분석한다. 반면 wireless_files 는 같은 구간을 **다른
    # 위치에서 동시에** 관측한 별개 스니퍼로, TSF 정렬 + dedup 경로를 탄다.
    file: List[UploadFile] = File(...),
    wireless_files: List[UploadFile] = File([]),
    wired_file: List[UploadFile] = File([]),
    # STA 로그 세트 — 파일명에 `<호기>/<파일>` 상대경로가 들어온다.
    station_log_files: List[UploadFile] = File([]),
    ssid: str = Form(""),
    passphrase: str = Form(""),
    mac_filter: str = Form(""),
    ip_filter: str = Form(""),
    time_start: str = Form(""),
    time_end: str = Form(""),
    client_job_id: str = Form(""),
):
    tshark = config.detect_tshark()
    if not tshark:
        return JSONResponse(error_payload(ErrorCode.TSHARK_MISSING), status_code=500)

    # 브라우저는 미선택 file input도 빈 filename 파트로 보낸다 — filename으로 판별
    valid_wireless_files = [wf for wf in wireless_files if wf is not None and (wf.filename or "")]
    if 1 + len(valid_wireless_files) > _MAX_WIRELESS_FILES:
        return JSONResponse(error_payload(ErrorCode.TOO_MANY_FILES), status_code=400)

    # 한 요청이 임시 파일로 쓰는 총량을 조각·관측점·STA 로그에 걸쳐 합산한다.
    budget = _UploadBudget()
    primary_files = [f for f in file if f is not None and (f.filename or "")]
    if not primary_files:
        return JSONResponse(error_payload(ErrorCode.EMPTY_FILE), status_code=400)
    tmp_name, primary_names, err = await _save_capture_group(primary_files, budget)
    if err is not None:
        return err
    name = merged_display_name(primary_names)

    # 추가 무선 파일들(w2, w3, …) — 하나라도 실패하면 그때까지 저장된 것 전부 정리
    wireless_tmps: List[str] = []
    wireless_names: List[str] = []
    for wf in valid_wireless_files:
        try:
            wtmp, werr = await _save_pcap_upload(wf, budget)
        except Exception:
            _cleanup_tmps(tmp_name, *wireless_tmps)
            raise
        if werr is not None:
            # wtmp는 _save_pcap_upload의 계약상(위 docstring) 이미 None이지만
            # (에러 반환 시 자체 tmp를 self-clean함), 방어적으로 함께 넘긴다 —
            # _cleanup_tmps는 falsy 값을 조용히 skip하므로 무해하다(PR #23
            # 리뷰 8라운드 Finding B).
            _cleanup_tmps(tmp_name, wtmp, *wireless_tmps)
            return werr
        wireless_tmps.append(wtmp)
        wireless_names.append(wf.filename)

    wired_tmp = ""
    wired_name = ""
    wired_files = [f for f in (wired_file or []) if f is not None and (f.filename or "")]
    if wired_files:
        try:
            wired_tmp, wired_names, werr = await _save_capture_group(wired_files, budget)
        except Exception:
            _cleanup_tmps(tmp_name, *wireless_tmps)
            raise
        if werr is not None:
            wired_tmp = ""
            _cleanup_tmps(tmp_name, *wireless_tmps)
            return werr
        wired_name = merged_display_name(wired_names)

    station_entries: List[dict] = []
    station_tmps: List[str] = []
    valid_station_files = [
        f for f in (station_log_files or []) if f is not None and (f.filename or "")
    ]
    if valid_station_files:
        try:
            station_entries, station_tmps, serr = await _save_station_logs(valid_station_files, budget)
        except Exception:
            _cleanup_tmps(tmp_name, wired_tmp, *wireless_tmps)
            raise
        if serr is not None:
            _cleanup_tmps(tmp_name, wired_tmp, *wireless_tmps)
            return serr

    # 클라이언트가 미리 만든 job_id를 우선 사용(본인 job만 폴링/취소하기 위함).
    # 미제공·형식오류·이미 active한 id와 충돌하면 서버가 uuid를 생성한다.
    job_id = _sanitize_job_id(client_job_id)
    cancel_event = threading.Event()

    # 이 시점에는 wired_tmp/wireless_tmps가 이미 디스크에 저장돼 있을 수 있다(위
    # 저장 성공 경로) — 아래 job 등록이 예외를 던지면 이후의 try/finally(실행
    # 구간)에 진입하지 못해 tmp들이 정리되지 않는다. 저장 자체의 예외 가드와
    # 같은 패턴으로 여기도 감싼다.
    try:
        with _jobs_lock:
            if not job_id or (job_id in _jobs and _jobs[job_id].get("active")):
                job_id = str(uuid.uuid4())
            _jobs[job_id] = {
                "msg": "분석 준비 중...",
                "pct": 0,
                "active": True,
                "created": time.time(),
                "cancel": cancel_event,
                "tmp": tmp_name,
                "wired_tmp": wired_tmp,
                "wireless_tmps": list(wireless_tmps),
                "station_tmps": list(station_tmps),
            }
            _prune_jobs_locked()
    except Exception:
        _cleanup_tmps(tmp_name, wired_tmp, *wireless_tmps, *station_tmps)
        raise

    def progress_cb(msg, pct):
        _set_progress(job_id, msg, pct, active=True)

    def _run():
        return run_analysis(
            tmp_name,
            ssid=ssid,
            passphrase=passphrase,
            time_start=time_start,
            time_end=time_end,
            mac_filter=mac_filter,
            ip_filter=ip_filter,
            wireless_paths=wireless_tmps,
            wired_path=wired_tmp,
            station_logs=station_entries,
            cancel_event=cancel_event,
            progress_cb=progress_cb,
        )

    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _run)
    finally:
        # _cleanup_tmps가 경로별 OSError를 내부에서 자체 흡수하므로(Windows
        # 백신/인덱서 잠금 등) 여기서 다시 감쌀 필요가 없다 — 감싸면 절대
        # 실행되지 않는 except 블록과 함께 "밖에서 흡수해야 한다"는 허위
        # 인상을 준다(PR #23 리뷰 7라운드 Finding B).
        _cleanup_tmps(tmp_name, wired_tmp, *wireless_tmps, *station_tmps)
        _set_progress(job_id, "완료", 100, active=False)

    if "error" in result:
        # pipeline이 error_code를 명시했으면(예: 잘못된 시간 필터 문자열)
        # 그 코드로 payload를 구성하고 400(클라이언트 입력 오류 — 사용자가
        # 값을 정정하면 해결됨)을 반환한다. 명시가 없으면(추출 실패 등
        # 서버/환경 쪽 문제로 간주) 기존처럼 일괄 NO_FRAMES(500)로 폴백한다
        # — 그러지 않으면 "시간 값을 고치세요"가 정답인 상황에서도 사용자가
        # "tshark/pcap 파일을 확인하라"는 엉뚱한 안내를 받는다(PR #23 리뷰
        # 6라운드 Finding A).
        error_code = result.get("error_code")
        if error_code:
            try:
                payload = error_payload(ErrorCode(error_code))
            except ValueError:
                error_code = None
                payload = error_payload(ErrorCode.NO_FRAMES)
            payload["job_id"] = job_id
            return JSONResponse(payload, status_code=400 if error_code else 500)
        payload = error_payload(ErrorCode.NO_FRAMES)
        payload["job_id"] = job_id
        return JSONResponse(payload, status_code=500)
    if result.get("cancelled"):
        payload = error_payload(ErrorCode.CANCELLED)
        payload["job_id"] = job_id
        return JSONResponse(payload, status_code=499)

    result["pcap_name"] = name
    # sources의 임시 파일명을 업로드 순서(w1..wN) 기준 원본 파일명으로 치환.
    # 파이프라인은 [file] + wireless_files 순서 그대로 role=="wireless" 항목을
    # w1..wN으로 생성하므로(0건이어도 항목은 남는다) 개수는 항상 일치해야 한다.
    # 불일치 시(방어적으로) 치환을 생략해 tmp 파일명이 그대로 노출되는 편이
    # 잘못된 이름을 붙이는 것보다 안전하다.
    all_wireless_names = [name] + wireless_names
    wireless_sources = [
        src for src in result.get("structured", {}).get("sources") or []
        if src.get("role") == "wireless"
    ]
    if len(wireless_sources) == len(all_wireless_names):
        for src, orig_name in zip(wireless_sources, all_wireless_names):
            src["name"] = orig_name
    for src in result.get("structured", {}).get("sources") or []:
        if src.get("role") == "wired" and wired_name:
            src["name"] = wired_name
    pcap_names = list(all_wireless_names)
    if wired_name:
        pcap_names.append(wired_name)
    if len(pcap_names) > 1:
        result["pcap_names"] = pcap_names
    analysis_id = result["id"]
    data_dir = config.ensure_data_dir()
    result_path = data_dir / f"{analysis_id}.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, default=str), encoding="utf-8")
    write_analysis_meta(analysis_id, result)

    return JSONResponse({
        "id": analysis_id,
        "job_id": job_id,
        "redirect": f"/analysis/{analysis_id}",
    })


@router.post("/api/cancel/{job_id}")
async def cancel_job(job_id: str):
    """특정 job 취소."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return JSONResponse({"error": "job not found"}, status_code=404)
        if not job["active"]:
            return JSONResponse({"status": "already_finished"})
        job["cancel"].set()
        return JSONResponse({"status": "cancelled", "job_id": job_id})


@router.post("/api/cancel")
async def cancel_all():
    """하위호환: 진행 중인 모든 분석 취소."""
    cancelled = []
    with _jobs_lock:
        for jid, job in _jobs.items():
            if job["active"]:
                job["cancel"].set()
                cancelled.append(jid)
    if not cancelled:
        return JSONResponse({"status": "no_running_analysis"})
    return JSONResponse({"status": "cancelled", "job_ids": cancelled})
