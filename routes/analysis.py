"""분석 결과 조회 + 시각화 데이터 API."""

import json
from typing import Any, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

import config
from analyzer.casefile_builder import build_casefile
from analyzer.casefile_schema import CasefileV1
from analyzer.casefile_serializer import (
    render_casefile_html,
    render_casefile_text,
    validate_casefile,
)
from analyzer.errors import ErrorCode, error_payload
from analyzer.web.pdf import PdfRenderError, is_pdf_available, render_pdf_from_html
from analyzer.web.report import build_report_markdown
from analyzer.web.report_html import render_report_html

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _load_result(analysis_id: str) -> Optional[dict[str, Any]]:
    path = config.safe_analysis_path(analysis_id)
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _load_result_checked(
    analysis_id: str,
) -> Tuple[Optional[dict[str, Any]], Optional[JSONResponse]]:
    path = config.safe_analysis_path(analysis_id)
    if path is None:
        return None, JSONResponse(
            error_payload(ErrorCode.INVALID_ANALYSIS_ID), status_code=400
        )
    if not path.exists():
        return None, JSONResponse(
            error_payload(ErrorCode.ANALYSIS_NOT_FOUND), status_code=404
        )
    try:
        return json.loads(path.read_text()), None
    except (json.JSONDecodeError, OSError):
        return None, JSONResponse(
            error_payload(ErrorCode.ANALYSIS_NOT_FOUND), status_code=404
        )


def _safe_filename_id(analysis_id: str) -> str:
    """다운로드 파일명용 ID 정제 — 영숫자·_-만 허용, 64자 절단, 빈값 fallback."""
    return (
        "".join(c for c in analysis_id if c.isalnum() or c in "_-")[:64] or "analysis"
    )


def _build_casefile_or_error(result: dict[str, Any], incident_id: str = ""):
    try:
        payload = build_casefile(result, incident_id=incident_id)
        return validate_casefile(payload), None
    except KeyError:
        return None, JSONResponse(
            error_payload(ErrorCode.INCIDENT_NOT_FOUND), status_code=404
        )
    except ValueError:
        return None, JSONResponse(
            error_payload(ErrorCode.CASEFILE_UNAVAILABLE), status_code=422
        )
    except Exception:
        return None, JSONResponse(
            error_payload(ErrorCode.CASEFILE_UNAVAILABLE), status_code=422
        )


@router.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_page(request: Request, analysis_id: str):
    result = _load_result(analysis_id)
    if not result:
        msg = error_payload(ErrorCode.ANALYSIS_NOT_FOUND)["error"]
        return HTMLResponse(f"<h1>{msg}</h1>", status_code=404)
    return templates.TemplateResponse(
        request,
        "analysis.html",
        {
            "result": result,
            "result_json": json.dumps(
                result.get("structured", {}), ensure_ascii=False, default=str
            ),
            "offline_assets": config.is_offline_assets(),
            "pdf_available": is_pdf_available(),
        },
    )


@router.get("/api/analysis/{analysis_id}")
async def analysis_data(analysis_id: str):
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        return error
    return JSONResponse(result)


@router.delete("/api/analysis/{analysis_id}")
async def delete_analysis(analysis_id: str):
    path = config.safe_analysis_path(analysis_id)
    if path is None:
        return JSONResponse(
            error_payload(ErrorCode.INVALID_ANALYSIS_ID), status_code=400
        )
    if not path.exists():
        return JSONResponse(
            error_payload(ErrorCode.ANALYSIS_NOT_FOUND), status_code=404
        )
    path.unlink()
    return JSONResponse({"status": "deleted"})


@router.get("/api/analysis/{analysis_id}/report.md")
async def analysis_report_markdown(analysis_id: str):
    """분석 결과를 외부 공유용 마크다운으로 export.

    구성: 메타 + 건강도 + 종합 결론(correlations) + 단일 진단(issues) +
    STA별 진단 + AI 가설. 표준 GFM이라 pandoc/typora 등으로 PDF·HTML
    추가 변환 가능.
    """
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        return error
    assert result is not None
    md = build_report_markdown(result)
    safe_id = _safe_filename_id(analysis_id)
    return PlainTextResponse(
        md,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="report_{safe_id}.md"',
        },
    )


@router.get("/analysis/{analysis_id}/report", response_class=HTMLResponse)
async def analysis_report_print_view(analysis_id: str):
    """인쇄용 리포트 HTML — 브라우저 인쇄(Ctrl+P → PDF 저장)가 기본 경로.

    playwright 없는 환경(폐쇄망 Windows 포함)에서도 항상 동작하는 PDF
    획득 수단. 서버측 PDF(report.pdf)와 같은 HTML을 쓴다.
    """
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        code = (
            ErrorCode.INVALID_ANALYSIS_ID
            if error.status_code == 400
            else ErrorCode.ANALYSIS_NOT_FOUND
        )
        msg = error_payload(code)["error"]
        return HTMLResponse(f"<h1>{msg}</h1>", status_code=error.status_code)
    assert result is not None
    return HTMLResponse(render_report_html(result))


@router.get("/api/analysis/{analysis_id}/report.pdf")
def analysis_report_pdf(analysis_id: str):
    """분석 리포트를 서버에서 PDF로 생성 — playwright 설치 환경 전용 선택 기능.

    sync playwright API를 쓰므로 의도적으로 `def` 선언 (FastAPI threadpool
    실행) — async로 바꾸면 이벤트 루프와 충돌한다. 미설치 시 501과 함께
    인쇄용 리포트 대안을 hint로 안내.
    """
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        return error
    assert result is not None
    if not is_pdf_available():
        return JSONResponse(
            error_payload(ErrorCode.PDF_EXPORT_UNAVAILABLE), status_code=501
        )
    try:
        pdf_bytes = render_pdf_from_html(render_report_html(result))
    except PdfRenderError:
        return JSONResponse(
            error_payload(ErrorCode.PDF_RENDER_FAILED), status_code=500
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="report_{_safe_filename_id(analysis_id)}.pdf"'
            ),
        },
    )


@router.get("/api/analysis/{analysis_id}/text")
async def analysis_text(analysis_id: str):
    """기존 텍스트 리포트 형식으로 내보내기."""
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        return error
    assert result is not None
    sections = result.get("text_sections", [])
    lines = ["WLAN Pcap 종합 분석 리포트", f"파일: {result.get('pcap_name', '?')}", ""]
    for sec in sections:
        lines.append(f"{'=' * 60}")
        lines.append(sec["title"])
        lines.append(f"{'=' * 60}")
        lines.extend(sec.get("lines", []))
        lines.append("")
    return PlainTextResponse("\n".join(lines))


@router.get("/api/analysis/{analysis_id}/casefile", response_model=CasefileV1)
async def analysis_casefile_json(analysis_id: str, incident_id: str = ""):
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        return error
    assert result is not None
    casefile, error = _build_casefile_or_error(result, incident_id=incident_id)
    if error is not None:
        return error
    assert casefile is not None
    return casefile


@router.get("/api/analysis/{analysis_id}/casefile/text")
async def analysis_casefile_text(analysis_id: str, incident_id: str = ""):
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        return error
    assert result is not None
    casefile, error = _build_casefile_or_error(result, incident_id=incident_id)
    if error is not None:
        return error
    assert casefile is not None
    return PlainTextResponse(render_casefile_text(casefile))


@router.get("/analysis/{analysis_id}/casefile", response_class=HTMLResponse)
async def analysis_casefile_html(
    request: Request, analysis_id: str, incident_id: str = ""
):
    del request
    result, error = _load_result_checked(analysis_id)
    if error is not None:
        code = (
            ErrorCode.INVALID_ANALYSIS_ID
            if error.status_code == 400
            else ErrorCode.ANALYSIS_NOT_FOUND
        )
        msg = error_payload(code)["error"]
        return HTMLResponse(f"<h1>{msg}</h1>", status_code=error.status_code)
    assert result is not None
    casefile, error = _build_casefile_or_error(result, incident_id=incident_id)
    if error is not None:
        code = (
            ErrorCode.INCIDENT_NOT_FOUND
            if error.status_code == 404
            else ErrorCode.CASEFILE_UNAVAILABLE
        )
        msg = error_payload(code)["error"]
        return HTMLResponse(f"<h1>{msg}</h1>", status_code=error.status_code)
    assert casefile is not None
    return HTMLResponse(render_casefile_html(casefile))
