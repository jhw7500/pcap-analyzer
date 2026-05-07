"""E2E 테스트 공통 fixture — 서버 자동 시작/종료."""
import subprocess
import sys
import time
import socket

import pytest

pytest.importorskip("playwright")


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


@pytest.fixture(scope="session")
def e2e_server():
    """FastAPI 서버를 백그라운드로 시작하고 테스트 후 종료."""
    if _port_open(8000):
        # 이미 실행 중이면 그대로 사용
        yield "http://localhost:8000"
        return

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 서버 시작 대기 (최대 10초)
    for _ in range(20):
        if _port_open(8000):
            break
        time.sleep(0.5)
    else:
        proc.kill()
        pytest.skip("서버 시작 실패")

    yield "http://localhost:8000"

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def browser_page(e2e_server):
    """Playwright 브라우저 페이지."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        yield page, e2e_server
        browser.close()
