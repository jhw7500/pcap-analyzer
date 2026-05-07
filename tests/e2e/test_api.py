"""E2E: API 엔드포인트 검증."""
import pytest

pytestmark = pytest.mark.e2e


class TestAPIEndpoints:
    def test_progress_api(self, browser_page):
        page, base = browser_page
        resp = page.request.get(f"{base}/api/progress")
        assert resp.status == 200
        data = resp.json()
        assert "pct" in data
        assert "msg" in data

    def test_analysis_not_found(self, browser_page):
        page, base = browser_page
        resp = page.request.get(f"{base}/api/analysis/nonexistent_12345")
        assert resp.status == 404

    def test_cancel_no_running(self, browser_page):
        page, base = browser_page
        resp = page.request.post(f"{base}/api/cancel")
        assert resp.status == 200
        assert resp.json()["status"] == "no_running_analysis"
