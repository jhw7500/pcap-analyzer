"""시스템/AI 설정 페이지."""
import os

from urllib.parse import urlparse

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import config

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _safe_next(url: str) -> str:
    """오픈 리다이렉트 방지: 같은 호스트의 경로만 허용. 그 외엔 '/'."""
    if not url:
        return "/"
    parsed = urlparse(url)
    # 외부 호스트로의 리다이렉트 차단
    if parsed.scheme and parsed.netloc:
        return parsed.path or "/" if not parsed.netloc else "/"
    path = parsed.path or "/"
    if not path.startswith("/"):
        return "/"
    if path.startswith("/settings"):
        return "/"
    return path + (("?" + parsed.query) if parsed.query else "")


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, next: str = ""):
    tshark = config.detect_tshark()
    cfg = config.get_all()
    # ?next= 쿼리 우선, 없으면 Referer에서 추출
    next_url = next.strip()
    if not next_url:
        referer = request.headers.get("referer", "")
        if referer:
            parsed = urlparse(referer)
            if parsed.path and not parsed.path.startswith("/settings"):
                next_url = parsed.path + (("?" + parsed.query) if parsed.query else "")
    return templates.TemplateResponse(request, "settings.html", {
        "tshark": tshark,
        "config": cfg,
        "ai_api_key_hint": config.mask_secret(cfg.get("ai_api_key", "")),
        "offline_assets": config.is_offline_assets(),
        "current_max_upload_mb": config.max_upload_size() // (1024 * 1024),
        "env_max_upload_mb": os.environ.get("PCAP_MAX_UPLOAD_MB", "").strip(),
        "next_url": _safe_next(next_url),
    })


@router.post("/settings")
async def save_settings(
    tshark_path: str = Form(""),
    ai_provider: str = Form(""),
    ai_api_key: str = Form(""),
    ai_model: str = Form(""),
    ai_auto_review: str = Form(""),
    ui_offline_assets: str = Form(""),
    max_upload_mb: str = Form(""),
    next: str = Form(""),
):
    if tshark_path:
        config.set_value("tshark_path", tshark_path)
    if ai_provider:
        config.set_value("ai_provider", ai_provider)
    if ai_api_key:
        config.set_value("ai_api_key", ai_api_key)
    if ai_model:
        config.set_value("ai_model", ai_model)
    config.set_value("ai_auto_review", ai_auto_review)
    config.set_value("ui_offline_assets", ui_offline_assets)
    config.set_value("max_upload_mb", max_upload_mb.strip())
    return RedirectResponse(_safe_next(next), status_code=303)
