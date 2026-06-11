"""인쇄용 HTML 렌더러 테스트 — 보안 핀(script escape, image 비활성) 포함."""

from analyzer.web.report_html import render_report_html


def _result(**overrides):
    """최소 분석 result — 단일 진단 표가 렌더되도록 issues 포함."""
    base = {
        "pcap_name": "테스트.pcap",
        "analyzed_at": "2026-01-01 00:00:00",
        "structured": {
            "overview": {"total_frames": 100, "duration_sec": 10},
            "diagnosis": {
                "health": {"score": 80, "grade": "good"},
                "issues": [
                    {
                        "severity": "high",
                        "category": "rssi",
                        "msg": "약신호 구간",
                        "action": "AP 위치 조정",
                    },
                ],
            },
        },
    }
    base.update(overrides)
    return base


class TestRenderReportHtml:
    def test_gfm_table_rendered(self):
        html = render_report_html(_result())
        assert "<table>" in html
        assert "<thead>" in html
        assert "약신호 구간" in html

    def test_script_injection_escaped(self):
        """html=False 핀 — 회귀하면 headless 렌더에서 LLM 유래 스크립트가 살아남."""
        html = render_report_html(_result(ai_review="<script>alert(1)</script>"))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_image_rule_disabled(self):
        """image rule 비활성 핀 — 회귀하면 headless에서 외부 fetch(SSRF성) 표면."""
        html = render_report_html(
            _result(ai_review="![x](http://evil.example/x.png)")
        )
        assert "<img" not in html
        # 양성 마커 — 페이로드가 출력에 실제 도달했음을 증명 (vacuous 통과 방지).
        # image rule 비활성 시 ![x](url)의 링크 부분이 <a href>로 살아남는다.
        assert "evil.example" in html

    def test_korean_preserved(self):
        html = render_report_html(_result())
        assert "WLAN Pcap 종합 분석 리포트" in html
        assert "테스트.pcap" in html

    def test_print_css_included(self):
        html = render_report_html(_result())
        assert "@page" in html
        assert "A4" in html

    def test_invalid_result_safe(self):
        """비정상 입력에서도 예외 없이 유효한 HTML 골격을 반환."""
        for bad in (None, [], "x", {}):
            html = render_report_html(bad)
            assert html.startswith("<!DOCTYPE html>")
            assert "</html>" in html

    def test_light_scheme(self):
        """인쇄용은 light — 대시보드 다크 배경이 섞이면 안 됨."""
        html = render_report_html(_result())
        assert "color-scheme: light" in html
