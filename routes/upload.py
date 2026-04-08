"""pcap 업로드 + 분석 실행 + 취소."""
import asyncio
import json
import tempfile
import threading
from pathlib import Path

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import config
from analyzer.pipeline import run_analysis

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# 진행 중인 분석 추적: {key: {"cancel": threading.Event, "tmp": str}}
_running: dict = {}
_running_lock = threading.Lock()


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

    content = await file.read()
    if len(content) > config.MAX_UPLOAD_SIZE:
        return JSONResponse(
            {"error": f"파일 크기가 {config.MAX_UPLOAD_SIZE // (1024*1024)}MB를 초과합니다."},
            status_code=413,
        )

    name = file.filename or "unknown.pcap"
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        return JSONResponse(
            {"error": "지원하지 않는 파일 형식입니다. .pcap, .pcapng, .cap만 가능합니다."},
            status_code=400,
        )

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(name).suffix)
    tmp.write(content)
    tmp.close()

    cancel_event = threading.Event()
    run_key = tmp.name

    with _running_lock:
        _running[run_key] = {"cancel": cancel_event, "tmp": tmp.name}

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
        )

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run)
    finally:
        with _running_lock:
            _running.pop(run_key, None)
        Path(tmp.name).unlink(missing_ok=True)

    if "error" in result:
        return JSONResponse({"error": result["error"]}, status_code=500)
    if result.get("cancelled"):
        return JSONResponse({"error": "분석이 취소되었습니다."}, status_code=499)

    analysis_id = result["id"]
    data_dir = config.ensure_data_dir()
    result_path = data_dir / f"{analysis_id}.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, default=str))

    return JSONResponse({"id": analysis_id, "redirect": f"/analysis/{analysis_id}"})


@router.post("/api/cancel")
async def cancel_analysis():
    """진행 중인 분석을 취소한다."""
    with _running_lock:
        if not _running:
            return JSONResponse({"status": "no_running_analysis"})
        for key, info in _running.items():
            info["cancel"].set()
        return JSONResponse({"status": "cancelled"})
