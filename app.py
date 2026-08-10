"""WLAN Pcap Analyzer 로컬 웹 대시보드."""
import os

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
from analyzer.core.extractor import detect_tshark_version
from routes.upload import router as upload_router
from routes.analysis import router as analysis_router
from routes.settings import router as settings_router
from routes.ai_review import router as ai_review_router

app = FastAPI(title="WLAN Pcap Analyzer")

# 분석 페이지는 structured 전체를 HTML에 인라인해 2시간 캡처에서 34MB 단일
# 문서가 된다. 초당 시계열·ping 전수목록 같은 반복 구조라 압축률이 매우 높아
# (실측 gzip -6 기준 1/10 수준) 원격 접속에서 전송량이 결정적으로 줄어든다.
# compresslevel은 starlette 기본값 9 대신 6 — 34MB를 매 요청 압축하는 비용이
# 응답 경로에 그대로 실리므로 비율 대비 CPU가 유리한 지점을 택했다.
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(settings_router)
app.include_router(ai_review_router)


@app.middleware("http")
async def _no_cache_static(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate, max-age=0"
    return response


@app.on_event("startup")
async def startup():
    config.ensure_data_dir()
    tshark = config.detect_tshark()
    if tshark:
        info = detect_tshark_version(tshark)
        print(f"tshark 감지됨: {tshark} (버전: {info['version']})")
    else:
        print("WARNING: tshark를 찾을 수 없습니다. 설정 페이지에서 경로를 지정하세요.")


def _run_dev_server():
    """개발/배포 공용 엔트리: env override 지원."""
    uvicorn.run(
        "app:app",
        host=os.getenv("PCAP_HOST", "0.0.0.0"),
        port=int(os.getenv("PCAP_PORT", "8000")),
        reload=os.getenv("PCAP_DEV_RELOAD", "true").lower() == "true",
    )


if __name__ == "__main__":
    _run_dev_server()
