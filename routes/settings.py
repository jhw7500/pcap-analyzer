"""시스템/AI 설정 페이지."""
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import config

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    tshark = config.detect_tshark()
    cfg = config.get_all()
    return templates.TemplateResponse(request, "settings.html", {
        "tshark": tshark,
        "config": cfg,
        "ai_api_key_hint": config.mask_secret(cfg.get("ai_api_key", "")),
        "offline_assets": config.is_offline_assets(),
    })


@router.post("/settings")
async def save_settings(
    tshark_path: str = Form(""),
    ai_provider: str = Form(""),
    ai_api_key: str = Form(""),
    ai_model: str = Form(""),
    ai_auto_review: str = Form(""),
    ui_offline_assets: str = Form(""),
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
    return RedirectResponse("/settings", status_code=303)
