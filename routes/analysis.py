"""분석 결과 조회 + 시각화 데이터 API."""
import json
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import config

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _load_result(analysis_id: str) -> Optional[dict]:
    path = config.ensure_data_dir() / f"{analysis_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


@router.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_page(request: Request, analysis_id: str):
    result = _load_result(analysis_id)
    if not result:
        return HTMLResponse("<h1>분석 결과를 찾을 수 없습니다.</h1>", status_code=404)
    return templates.TemplateResponse("analysis.html", {
        "request": request,
        "result": result,
        "result_json": json.dumps(result.get("structured", {}), ensure_ascii=False, default=str),
    })


@router.get("/api/analysis/{analysis_id}")
async def analysis_data(analysis_id: str):
    result = _load_result(analysis_id)
    if not result:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(result)


@router.get("/api/analysis/{analysis_id}/text")
async def analysis_text(analysis_id: str):
    """기존 텍스트 리포트 형식으로 내보내기."""
    result = _load_result(analysis_id)
    if not result:
        return JSONResponse({"error": "not found"}, status_code=404)
    sections = result.get("text_sections", [])
    lines = [f"WLAN Pcap 종합 분석 리포트", f"파일: {result.get('pcap_name', '?')}", ""]
    for sec in sections:
        lines.append(f"{'=' * 60}")
        lines.append(sec["title"])
        lines.append(f"{'=' * 60}")
        lines.extend(sec.get("lines", []))
        lines.append("")
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines))
