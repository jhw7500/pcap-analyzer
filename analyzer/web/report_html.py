"""분석 리포트 → 인쇄용 standalone HTML.

build_report_markdown() 출력을 단일 출처로 재사용 — report.md와 인쇄
뷰/PDF 간 내용 drift를 원천 차단한다. 1차 사용 경로는 브라우저 인쇄
(Ctrl+P → PDF 저장)이고, 같은 HTML을 서버측 PDF 렌더(analyzer/web/pdf.py)가
입력으로 쓴다.

보안 핀 (tests/test_report_html.py가 회귀 감시):
- html=False — AI 가설 등 외부 유래 마크다운의 raw HTML을 escape.
- image rule 비활성 — ``![..](url)`` 이 <img>로 렌더되면 headless 렌더
  단계에서 외부 fetch(SSRF성) 표면이 생기므로 차단.
"""
import html as _html
from typing import Any, Dict

from markdown_it import MarkdownIt

from analyzer.web.report import build_report_markdown

# commonmark preset은 html=True가 기본이라 명시적으로 끈다. gfm-like preset은
# linkify-it-py 추가 의존을 끌고 오므로 쓰지 않는다 (표는 enable로 충분).
_md = MarkdownIt("commonmark", {"html": False}).enable("table")
_md.disable("image")

_PRINT_CSS = """
:root { color-scheme: light; }
@page { size: A4; margin: 14mm; }
body {
  font-family: 'Malgun Gothic', 'Noto Sans CJK KR', 'NanumGothic', sans-serif;
  color: #111; background: #fff;
  font-size: 11pt; line-height: 1.55;
  max-width: 180mm; margin: 0 auto; padding: 8mm;
  print-color-adjust: exact; -webkit-print-color-adjust: exact;
}
h1 { font-size: 17pt; border-bottom: 2px solid #333; padding-bottom: 4px; }
h2 { font-size: 13.5pt; margin-top: 1.3em; border-bottom: 1px solid #999; padding-bottom: 2px; }
h3 { font-size: 11.5pt; }
h1, h2, h3 { break-after: avoid; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; font-size: 9.5pt; }
thead { display: table-header-group; }
tr, td, th { break-inside: avoid; page-break-inside: avoid; }
th, td {
  border: 1px solid #bbb; padding: 3px 6px;
  text-align: left; vertical-align: top; overflow-wrap: anywhere;
}
th { background: #f0f0f0; }
code { background: #f4f4f4; padding: 0 3px; border-radius: 3px; font-size: 0.9em; overflow-wrap: anywhere; }
pre { background: #f4f4f4; padding: 8px; white-space: pre-wrap; overflow-wrap: break-word; }
hr { border: none; border-top: 1px solid #999; margin: 1.2em 0; }
ul, ol { padding-left: 1.4em; }
"""


def render_report_html(result: Dict[str, Any]) -> str:
    """분석 result → 인쇄용 standalone HTML (순수 함수).

    비정상 입력은 build_report_markdown의 fallback 마크다운으로 흡수되므로
    항상 유효한 HTML 골격을 반환한다.
    """
    body = _md.render(build_report_markdown(result))
    pcap_name = ""
    if isinstance(result, dict):
        pcap_name = str(result.get("pcap_name") or "")
    title = _html.escape(f"{pcap_name} 분석 리포트".strip())
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{title}</title>
<style>{_PRINT_CSS}</style>
</head>
<body>
{body}
</body>
</html>
"""
