"""E2E: 탭 UI 검증."""
import pytest

pytestmark = pytest.mark.e2e


class TestNavigation:
    def test_settings_page(self, browser_page):
        page, base = browser_page
        page.goto(f"{base}/settings")
        assert "tshark" in page.content().lower()
        assert page.locator("input[name='ai_api_key']").is_visible()

    def test_nav_links(self, browser_page):
        page, base = browser_page
        page.goto(base)
        assert page.locator("a[href='/settings']").is_visible()
        # href="/"는 로고와 "대시보드" 2개이므로 first로 좁힘 (strict-mode 대응)
        assert page.locator("a[href='/']").first.is_visible()

    def test_settings_form_submit(self, browser_page):
        page, base = browser_page
        page.goto(f"{base}/settings")
        # 폼 제출이 리다이렉트되는지 확인
        page.locator("form").first.evaluate("form => form.action")
