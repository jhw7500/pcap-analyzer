"""WLAN Pcap Analyzer 로컬 웹 대시보드."""
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
from routes.upload import router as upload_router
from routes.analysis import router as analysis_router
from routes.settings import router as settings_router

app = FastAPI(title="WLAN Pcap Analyzer")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(settings_router)


@app.on_event("startup")
async def startup():
    config.ensure_data_dir()
    tshark = config.detect_tshark()
    if tshark:
        print(f"tshark 감지됨: {tshark}")
    else:
        print("WARNING: tshark를 찾을 수 없습니다. 설정 페이지에서 경로를 지정하세요.")


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
