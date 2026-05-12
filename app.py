"""WLAN Pcap Analyzer 로컬 웹 대시보드."""
import os

import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
from analyzer.core.extractor import detect_tshark_version
from routes.upload import router as upload_router
from routes.analysis import router as analysis_router
from routes.settings import router as settings_router
from routes.ai_review import router as ai_review_router

app = FastAPI(title="WLAN Pcap Analyzer")

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
