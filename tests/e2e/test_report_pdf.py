"""report PDF 실통합 테스트 — 실제 chromium 렌더 (opt-in: make test-e2e).

라우트 로직은 tests/test_routes_extended.py의 monkeypatch 테스트가
playwright 없이 전 경로를 커버한다. 여기서는 모킹 없이 진짜 chromium으로
HTML→PDF 변환이 동작하는지만 검증한다.
"""
import pytest

pytest.importorskip("playwright")

pytestmark = pytest.mark.e2e


def test_render_pdf_real_chromium():
    from analyzer.web.pdf import is_pdf_available, render_pdf_from_html
    from analyzer.web.report_html import render_report_html

    assert is_pdf_available()
    html = render_report_html(
        {
            "pcap_name": "e2e_한글검증.pcap",
            "structured": {
                "overview": {"total_frames": 42, "duration_sec": 3},
                "diagnosis": {
                    "health": {"score": 90, "grade": "good"},
                    "issues": [
                        {
                            "severity": "low",
                            "category": "rssi",
                            "msg": "한글 메시지 렌더 확인",
                            "action": "조치 없음",
                        }
                    ],
                },
            },
        }
    )
    pdf = render_pdf_from_html(html)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000
