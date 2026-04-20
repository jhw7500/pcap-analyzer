"""pcap 업로드 + 분석 실행 + 취소 + 진행률 polling (job id 기반)."""
import asyncio
import json
import tempfile
import threading
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import config
from analyzer.core.pcap_magic import has_valid_pcap_magic
from analyzer.pipeline import run_analysis

_UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1MB
_JOBS_MAX = 100  # 최근 N개만 유지

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# job_id → {msg, pct, active, created, cancel, tmp}
_jobs: dict = {}
_jobs_lock = threading.Lock()


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
            meta = json.loads(f.read_text())
            analyses.append({
                "id": meta.get("id", f.stem),
                "pcap_name": meta.get("pcap_name", "?"),
                "frame_count": meta.get("frame_count", 0),
                "analyzed_at": meta.get("analyzed_at", "?"),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return templates.TemplateResponse(request, "index.html", {
        "tshark": tshark,
        "analyses": analyses,
        "offline_assets": config.is_offline_assets(),
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
    """하위호환: 가장 최근 active job의 진행률. 없으면 마지막 기록 또는 idle."""
    with _jobs_lock:
        if not _jobs:
            return JSONResponse({"msg": "", "pct": 0, "active": False})
        active = [j for j in _jobs.values() if j["active"]]
        target = max(active, key=lambda j: j["created"]) if active else \
                 max(_jobs.values(), key=lambda j: j["created"])
        return JSONResponse({
            "msg": target["msg"],
            "pct": target["pct"],
            "active": target["active"],
        })


@router.post("/api/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    ssid: str = Form(""),
    passphrase: str = Form(""),
    mac_filter: str = Form(""),
    ip_filter: str = Form(""),
    time_start: str = Form(""),
    time_end: str = Form(""),
):
    tshark = config.detect_tshark()
    if not tshark:
        return JSONResponse(
            {"error": "tshark가 설치되어 있지 않습니다. 설정 페이지에서 경로를 지정하세요."},
            status_code=500,
        )

    name = file.filename or "unknown.pcap"
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        return JSONResponse(
            {"error": "지원하지 않는 파일 형식입니다. .pcap, .pcapng, .cap만 가능합니다."},
            status_code=400,
        )

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
                    return JSONResponse(
                        {"error": "유효한 pcap/pcapng 포맷이 아닙니다."},
                        status_code=400,
                    )
                first_chunk = False
            total += len(chunk)
            if total > config.MAX_UPLOAD_SIZE:
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
                return JSONResponse(
                    {"error": f"파일 크기가 {config.MAX_UPLOAD_SIZE // (1024*1024)}MB를 초과합니다."},
                    status_code=413,
                )
            tmp.write(chunk)
    except Exception:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
        raise
    tmp.close()
    if first_chunk:
        Path(tmp.name).unlink(missing_ok=True)
        return JSONResponse(
            {"error": "빈 파일입니다."},
            status_code=400,
        )

    job_id = str(uuid.uuid4())
    cancel_event = threading.Event()

    with _jobs_lock:
        _jobs[job_id] = {
            "msg": "분석 준비 중...",
            "pct": 0,
            "active": True,
            "created": time.time(),
            "cancel": cancel_event,
            "tmp": tmp.name,
        }
        _prune_jobs_locked()

    def progress_cb(msg, pct):
        _set_progress(job_id, msg, pct, active=True)

    def _run():
        return run_analysis(
            tmp.name,
            ssid=ssid,
            passphrase=passphrase,
            time_start=time_start,
            time_end=time_end,
            mac_filter=mac_filter,
            ip_filter=ip_filter,
            cancel_event=cancel_event,
            progress_cb=progress_cb,
        )

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run)
    finally:
        Path(tmp.name).unlink(missing_ok=True)
        _set_progress(job_id, "완료", 100, active=False)

    if "error" in result:
        return JSONResponse({"error": result["error"], "job_id": job_id}, status_code=500)
    if result.get("cancelled"):
        return JSONResponse({"error": "분석이 취소되었습니다.", "job_id": job_id}, status_code=499)

    result["pcap_name"] = name
    analysis_id = result["id"]
    data_dir = config.ensure_data_dir()
    result_path = data_dir / f"{analysis_id}.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, default=str))

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
