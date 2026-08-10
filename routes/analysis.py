"""분석 결과 조회 + 시각화 데이터 API."""

import html
import json
import threading
from collections import OrderedDict
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


#: 파싱된 결과 캐시 — (경로, mtime_ns, size) → result dict. 2시간 캡처 결과는
#: 33MB라 요청마다 json.loads가 0.3~0.8초씩 이벤트 루프를 잡는다. 분석 페이지
#: 하나를 열면 페이지·report·casefile 등 같은 파일을 여러 번 읽으므로 소수만
#: 캐시해도 체감이 크다.
#:
#: **계약: 캐시된 dict를 변형하지 말 것.** 같은 객체가 다음 요청에도 그대로
#: 반환되므로 변형은 그 뒤 모든 응답을 오염시킨다. 현재 소비자(report,
#: casefile, 템플릿)는 전부 읽기 전용이고, 파일을 다시 쓰는 경로
#: (routes/ai_review.py)는 이 헬퍼를 쓰지 않고 자체 로드한다 — 그쪽이 파일을
#: 갱신하면 mtime/size가 바뀌어 캐시 키가 자연히 무효화된다.
_RESULT_CACHE_MAX = 2
_result_cache: "OrderedDict[tuple, dict[str, Any]]" = OrderedDict()
#: 캐시 접근 직렬화. `def` 엔드포인트는 FastAPI가 **스레드풀**로 내보내므로
#: (홈의 `index()`와 같은 이유) 여러 요청이 동시에 이 OrderedDict를 만진다.
#: 개별 dict 연산은 GIL 아래 원자적이지만 "조회 → 삽입 → LRU 축출"은 아니라,
#: 두 스레드가 같은 미스를 처리하면 `popitem`이 이미 빠진 키를 건드려 KeyError가
#: 날 수 있다. 파싱(33MB)은 잠금 **밖**에서 한다 — 안에서 하면 동시 요청이
#: 직렬화돼 캐시가 오히려 병목이 된다. 중복 파싱은 낭비일 뿐 오류가 아니다.
_result_cache_lock = threading.Lock()


def _read_result_cached(path) -> Optional[dict[str, Any]]:
    """경로의 결과 JSON을 파싱해 반환. mtime+size가 같으면 캐시를 재사용.

    실패(손상/인코딩/IO)면 None — 호출부가 각자의 에러 코드로 변환한다.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    key = (str(path), st.st_mtime_ns, st.st_size)
    with _result_cache_lock:
        cached = _result_cache.get(key)
        if cached is not None:
            _result_cache.move_to_end(key)
            return cached
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None
    with _result_cache_lock:
        _result_cache[key] = parsed
        _result_cache.move_to_end(key)
        while len(_result_cache) > _RESULT_CACHE_MAX:
            _result_cache.popitem(last=False)
    return parsed


def _invalidate_result_cache(path=None) -> None:
    """캐시 비우기. path를 주면 그 경로 항목만, 없으면 전부."""
    with _result_cache_lock:
        if path is None:
            _result_cache.clear()
            return
        target = str(path)
        for key in [k for k in _result_cache if k[0] == target]:
            _result_cache.pop(key, None)


def _load_result(analysis_id: str) -> Optional[dict[str, Any]]:
    path = config.safe_analysis_path(analysis_id)
    if path is None or not path.exists():
        return None
    return _read_result_cached(path)


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
    parsed = _read_result_cached(path)
    if parsed is None:
        return None, JSONResponse(
            error_payload(ErrorCode.ANALYSIS_CORRUPTED), status_code=500
        )
    return parsed, None


def _safe_filename_id(analysis_id: str) -> str:
    """다운로드 파일명용 ID 정제 — ASCII 영숫자·_-만 허용, 64자 절단, 빈값 fallback.

    ASCII 제한 필수: analysis_id는 pcap 파일명 stem을 포함하므로 한글 등
    비ASCII가 들어올 수 있는데, str.isalnum()은 유니코드 전체에 True라
    그대로 두면 Content-Disposition 헤더 인코딩(latin-1)에서 500이 난다.
    """
    return (
        "".join(
            c for c in analysis_id if (c.isascii() and c.isalnum()) or c in "_-"
        )[:64]
        or "analysis"
    )


def _html_safe_json(payload: Any) -> str:
    """`<script>` 블록 안에 그대로 심을 수 있는 JSON 문자열.

    json.dumps는 `<`, `>`, `&`를 이스케이프하지 않는다. structured에는 업로드
    **파일명**처럼 사용자가 정한 문자열이 실리므로(`sources[].name`), 이름에
    `</script>`가 들어 있으면 스크립트 블록이 거기서 닫히고 그 뒤가 마크업으로
    해석된다 — 저장형 XSS. `\\uXXXX` 이스케이프는 JSON 문자열 안에서 같은 문자로
    복원되므로 브라우저가 파싱해 얻는 값은 그대로다.

    U+2028/U+2029도 함께 이스케이프한다 — JSON에선 합법이지만 (ES2019 이전) JS
    소스에서는 줄바꿈으로 취급돼 스크립트를 깨뜨린다.

    Jinja의 `| tojson`(analysis.html의 다른 삽입부)도 같은 일을 하지만 여기서는
    쓰지 않는다: `default=str`(직렬화 불가 값 방어)과 `ensure_ascii=False`(한글이
    \\uXXXX로 부풀지 않게)가 필요하기 때문이다.
    """
    return (
        json.dumps(payload, ensure_ascii=False, default=str)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
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
            # `| safe`로 <script> 안에 그대로 심기므로 HTML-safe 직렬화가 필수다.
            "result_json": _html_safe_json(result.get("structured", {})),
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
    # 결과 파일이 사라졌으니 파싱 캐시와 홈 화면용 메타 사이드카도 함께 정리한다.
    _invalidate_result_cache(path)
    config.analysis_meta_path(analysis_id).unlink(missing_ok=True)
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
        msg = html.escape(error_payload(code)["error"])
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
        # 응답에는 catalog message/hint만 나가므로 원인(원본 예외)은 로그로 남긴다.
        import logging

        logging.getLogger(__name__).exception("PDF 렌더 실패: %s", analysis_id)
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
