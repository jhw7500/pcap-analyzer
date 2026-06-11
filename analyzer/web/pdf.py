"""서버측 PDF 렌더 — playwright(chromium) 설치 환경에서만 동작하는 선택 기능.

설치: ``pip install -r requirements-pdf.txt && playwright install chromium``
(chromium ~150MB CDN 다운로드 — 폐쇄망 불가). 미설치 환경에서는 라우트가
501(PDF_EXPORT_UNAVAILABLE)로 안내하고, 인쇄용 리포트(/analysis/{id}/report)가
항상 동작하는 대안이다.

주의: sync API 사용 — asyncio 이벤트 루프 안에서 호출하면 안 되므로
소비 라우트는 반드시 ``def``(FastAPI threadpool)로 선언한다.
"""
import importlib.util
import threading

_RENDER_TIMEOUT_MS = 30_000

# lock 대기 상한 — 선행 렌더가 chromium wedge 등으로 안 끝나도 후속
# 요청이 threadpool 스레드를 쥔 채 무기한 적체되지 않도록 fail-fast.
_LOCK_WAIT_TIMEOUT_S = 60

# 동시 렌더 직렬화 — 단일 사용자 도구에서 chromium 다중 기동으로
# 메모리가 튀는 것을 방지. 요청당 기동 비용은 수용 (재사용 최적화는
# 실측 병목 확인 전까지 미도입).
_render_lock = threading.Lock()


class PdfRenderError(Exception):
    """PDF 생성 실패 — chromium 기동/렌더/타임아웃 오류를 단일 타입으로 래핑."""


def is_pdf_available() -> bool:
    """playwright 모듈 존재 여부 — chromium 실존은 렌더 단계 예외로 흡수."""
    return importlib.util.find_spec("playwright") is not None


def render_pdf_from_html(html: str) -> bytes:
    """인쇄용 HTML → PDF bytes. 모든 실패는 PdfRenderError로 통일
    (손상된 playwright 설치의 ImportError 포함).

    보안: JS 비활성 컨텍스트 + 전체 네트워크 요청 차단 — 리포트에 유입된
    외부 유래 콘텐츠(AI 가설 등)가 headless 브라우저에서 실행되거나
    외부 요청을 일으키는 표면을 제거한다. 콘텐츠는 set_content로 직접
    주입하고 폰트는 시스템 폰트만 쓰므로 네트워크가 필요 없다.

    타임아웃 범위: 30s는 set_content 등 timeout 인자를 받는 단계까지만
    커버한다 — playwright의 page.pdf()는 timeout 옵션이 없어 chromium
    wedge 시 해당 요청은 회수되지 않는다. 대신 lock 대기에 상한을 둬
    후속 요청이 threadpool 스레드를 쥔 채 무기한 적체되는 것은 막는다.
    """
    if not _render_lock.acquire(timeout=_LOCK_WAIT_TIMEOUT_S):
        raise PdfRenderError(
            f"PDF 렌더 대기 {_LOCK_WAIT_TIMEOUT_S}s 초과 — 이전 렌더가 끝나지 않음"
        )
    try:
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch()
                try:
                    context = browser.new_context(java_script_enabled=False)
                    page = context.new_page()
                    page.route("**/*", lambda route: route.abort())
                    page.set_default_timeout(_RENDER_TIMEOUT_MS)
                    page.set_content(
                        html, wait_until="load", timeout=_RENDER_TIMEOUT_MS
                    )
                    return page.pdf(
                        format="A4",
                        print_background=True,
                        display_header_footer=True,
                        # isolated header/footer 컨텍스트는 시스템 한글 폰트가
                        # 안 잡힐 수 있어 ASCII+숫자만 사용.
                        header_template="<span></span>",
                        footer_template=(
                            '<div style="width:100%;text-align:center;'
                            'font-size:8px;color:#777;">'
                            '<span class="pageNumber"></span> / '
                            '<span class="totalPages"></span></div>'
                        ),
                        margin={
                            "top": "14mm",
                            "bottom": "16mm",
                            "left": "12mm",
                            "right": "12mm",
                        },
                    )
                finally:
                    browser.close()
        except Exception as exc:
            raise PdfRenderError(str(exc)) from exc
    finally:
        _render_lock.release()
