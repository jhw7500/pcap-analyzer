"""pcap 업로드 + 분석 실행 + 취소 + 진행률 polling (job id 기반)."""
import asyncio
import json
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import List

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import config
from analyzer.core.pcap_magic import has_valid_pcap_magic
from analyzer.errors import ErrorCode, error_payload
from analyzer.pipeline import run_analysis

_UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1MB
_JOBS_MAX = 100  # 최근 N개만 유지
_MAX_WIRELESS_FILES = 4  # 기본(file) 1개 + wireless_files 최대 3개

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


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    tshark = config.detect_tshark()
    data_dir = config.ensure_data_dir()
    analyses = []
    for f in sorted(data_dir.glob("*.json"), reverse=True):
        try:
            meta = json.loads(f.read_text(encoding="utf-8"))
            analyses.append({
                "id": meta.get("id", f.stem),
                "pcap_name": meta.get("pcap_name", "?"),
                "frame_count": meta.get("frame_count", 0),
                "analyzed_at": meta.get("analyzed_at", "?"),
            })
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


async def _save_pcap_upload(file: UploadFile):
    """업로드 파일 검증·임시 저장. 반환 (tmp_path, error_response) — 하나만 non-None."""
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


def _cleanup_tmps(*paths: str) -> None:
    """주어진 임시 경로들을 모두 unlink(존재하지 않아도 무시). 빈 문자열은 skip."""
    for p in paths:
        if p:
            Path(p).unlink(missing_ok=True)


@router.post("/api/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    wireless_files: List[UploadFile] = File([]),
    wired_file: UploadFile | None = File(None),
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

    name = file.filename or "unknown.pcap"
    tmp_name, err = await _save_pcap_upload(file)
    if err is not None:
        return err

    # 추가 무선 파일들(w2, w3, …) — 하나라도 실패하면 그때까지 저장된 것 전부 정리
    wireless_tmps: List[str] = []
    wireless_names: List[str] = []
    for wf in valid_wireless_files:
        try:
            wtmp, werr = await _save_pcap_upload(wf)
        except Exception:
            _cleanup_tmps(tmp_name, *wireless_tmps)
            raise
        if werr is not None:
            _cleanup_tmps(tmp_name, *wireless_tmps)
            return werr
        wireless_tmps.append(wtmp)
        wireless_names.append(wf.filename)

    wired_tmp = ""
    wired_name = ""
    if wired_file is not None and (wired_file.filename or ""):
        try:
            wired_tmp, werr = await _save_pcap_upload(wired_file)
        except Exception:
            _cleanup_tmps(tmp_name, *wireless_tmps)
            raise
        if werr is not None:
            wired_tmp = ""
            _cleanup_tmps(tmp_name, *wireless_tmps)
            return werr
        wired_name = wired_file.filename

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
            }
            _prune_jobs_locked()
    except Exception:
        _cleanup_tmps(tmp_name, wired_tmp, *wireless_tmps)
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
            cancel_event=cancel_event,
            progress_cb=progress_cb,
        )

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run)
    finally:
        try:
            _cleanup_tmps(tmp_name, wired_tmp, *wireless_tmps)
        except OSError:
            # Windows: 백신/인덱서가 임시파일을 잠그면 삭제가 실패할 수 있음 — 분석 결과는 보존
            pass
        _set_progress(job_id, "완료", 100, active=False)

    if "error" in result:
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
