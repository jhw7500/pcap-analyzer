"""analyzer/web/pdf.py 단위 테스트 — playwright 미설치 CI에서도 실행 가능.

실제 chromium 렌더는 tests/e2e/test_report_pdf.py (opt-in)가 담당.
여기서는 에러 래핑 계약과 lock 대기 상한만 검증한다.
"""
import sys
import types

import pytest

from analyzer.web import pdf as pdf_mod


class TestRenderPdfErrorWrapping:
    def test_broken_install_import_error_wrapped(self, monkeypatch):
        """손상 설치(find_spec 통과, import 실패)도 PdfRenderError로 래핑."""
        monkeypatch.setitem(sys.modules, "playwright", None)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
        with pytest.raises(pdf_mod.PdfRenderError):
            pdf_mod.render_pdf_from_html("<html></html>")

    def test_runtime_error_wrapped(self, monkeypatch):
        """sync_playwright 진입 실패(driver 오류 등)도 PdfRenderError로 래핑."""
        fake_api = types.ModuleType("playwright.sync_api")

        def _boom():
            raise RuntimeError("driver crashed")

        fake_api.sync_playwright = _boom
        monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
        monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_api)
        with pytest.raises(pdf_mod.PdfRenderError):
            pdf_mod.render_pdf_from_html("<html></html>")


class TestRenderLockTimeout:
    def test_lock_wait_timeout_fail_fast(self, monkeypatch):
        """선행 렌더가 lock을 쥔 채면 대기 상한 후 즉시 실패 — 무기한 적체 방지.

        timeout=0(논블로킹 acquire)으로 wall-clock 의존 없이 결정적으로 검증.
        """
        monkeypatch.setattr(pdf_mod, "_LOCK_WAIT_TIMEOUT_S", 0)
        assert pdf_mod._render_lock.acquire(timeout=1)
        try:
            with pytest.raises(pdf_mod.PdfRenderError):
                pdf_mod.render_pdf_from_html("<html></html>")
        finally:
            pdf_mod._render_lock.release()
