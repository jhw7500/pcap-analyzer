"""Playwright로 실제 브라우저에서 NET/AUS pcap을 업로드·분석·검증한다.

- 서버는 미리 8765 포트에서 띄워둬야 함
- 두 pcap을 차례로 업로드 → 결과 페이지 진입 → 탭별 스크린샷 + 핵심 수치 추출
- 출력: tmp/screenshots/{이름}_{탭}.png, stdout에 평가 요약
"""
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8765"
SSID = "cantops_3t"
PW = "iothub123!@"
ROOT = Path(__file__).resolve().parent.parent
SHOT_DIR = ROOT / "tmp" / "screenshots"

PCAPS = [
    ("NET_DATA1", ROOT / "tmp" / "NET_DATA1.pcapng"),
    ("AUS_DATA1", ROOT / "tmp" / "AUS_DATA1.pcapng"),
]

# 결과 페이지에서 확인할 탭들 (id 또는 텍스트 기반)
TABS = ["overview", "timeline", "roaming", "ping", "devices", "diagnosis"]


def upload_and_analyze(page, name: str, path: Path) -> str:
    print(f"\n[{name}] upload {path.name}", flush=True)
    page.goto(BASE)
    page.wait_for_selector("#upload-btn", timeout=10_000)

    page.set_input_files("#pcap-file", str(path))
    # 옵션은 <details> 안에 있음 — open 속성을 직접 추가하거나 summary 클릭
    page.evaluate("() => document.querySelectorAll('details').forEach(d => d.open = true)")
    page.fill('input[name="ssid"]', SSID)
    page.fill('input[name="passphrase"]', PW)
    page.click("#upload-btn")

    # 결과 페이지로 이동될 때까지 대기 (URL 변화 또는 분석 완료)
    page.wait_for_url(re.compile(r"/analysis/"), timeout=120_000)
    page.wait_for_load_state("networkidle", timeout=60_000)
    print(f"[{name}] result page: {page.url}", flush=True)
    return page.url


def capture_tab(page, name: str, tab: str) -> Path:
    """탭 클릭 후 차트 렌더링 대기 + 전체 페이지 스크린샷.

    Plotly 차트가 비동기 렌더링되므로 .js-plotly-plot SVG가 나타날 때까지 대기.
    """
    sel = f'[data-tab="{tab}"]'
    try:
        page.locator(sel).first.click()
    except Exception as e:
        print(f"[{name}/{tab}] click err: {e}", flush=True)
    # 탭 전환 직후 약간 대기
    page.wait_for_timeout(400)
    # 차트 렌더 대기 (해당 탭 안 .js-plotly-plot 또는 timeout)
    try:
        page.wait_for_function(
            f"() => {{const t=document.querySelector('#tab-{tab}');"
            "  if(!t) return true;"
            "  const plots=t.querySelectorAll('.js-plotly-plot');"
            "  if(plots.length===0) return true;"
            "  return Array.from(plots).every(p => p.querySelector('.main-svg'));}}",
            timeout=8000,
        )
    except Exception:
        pass
    page.wait_for_timeout(500)
    out = SHOT_DIR / f"{name}_{tab}.png"
    page.screenshot(path=str(out), full_page=True)
    return out


def extract_summary(page) -> dict:
    """결과 페이지에서 텍스트 기반 핵심 지표 추출."""
    body = page.evaluate("() => document.body.innerText")
    return {
        "raw_chars": len(body),
        "has_loss": "loss" in body.lower() or "손실" in body,
        "has_rtt": "rtt" in body.lower() or "RTT" in body,
        "has_health": "건강" in body or "health" in body.lower() or "양호" in body or "위험" in body,
        "snippets": _grep_lines(body),
    }


_NUM_PATTERNS = [
    r".*Loss.*%.*",
    r".*loss.*\d+.*",
    r".*RTT.*",
    r".*Retry.*\d+.*",
    r".*RSSI.*-?\d+.*",
    r".*Health.*\d+.*",
    r".*건강.*\d+.*",
    r".*양호.*",
    r".*위험.*",
    r".*프레임.*\d+.*",
    r".*48827.*",
    r".*loss_gap.*",
]


def _grep_lines(text: str) -> list:
    out = []
    seen = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or len(s) > 200:
            continue
        for pat in _NUM_PATTERNS:
            if re.match(pat, s, re.IGNORECASE):
                if s not in seen:
                    out.append(s)
                    seen.add(s)
                break
    return out[:40]


def main():
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    results = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1400, "height": 1000})
        page = ctx.new_page()

        for name, path in PCAPS:
            try:
                upload_and_analyze(page, name, path)
            except Exception as e:
                print(f"[{name}] ERROR upload: {e}", flush=True)
                continue
            shots = {}
            for tab in TABS:
                try:
                    shots[tab] = str(capture_tab(page, name, tab))
                except Exception as e:
                    print(f"[{name}] tab {tab} err: {e}", flush=True)
            summary = extract_summary(page)
            results[name] = {"shots": shots, "summary": summary}

        browser.close()

    print("\n===== PLAYWRIGHT VERIFY SUMMARY =====")
    for name, r in results.items():
        print(f"\n## {name}")
        for k, v in r["summary"].items():
            if k == "snippets":
                continue
            print(f"  {k}: {v}")
        print(f"  screenshots: {len(r['shots'])} ({list(r['shots'].keys())})")
        print("  key text lines:")
        for s in r["summary"]["snippets"]:
            print(f"    | {s}")


if __name__ == "__main__":
    sys.exit(main() or 0)
