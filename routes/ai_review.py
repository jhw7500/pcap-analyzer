"""AI 리뷰 API."""
import json
from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

import config
from analyzer.errors import ErrorCode, error_payload
from ai.prompts import build_review_prompt
from ai.reviewer import SYSTEM_PROMPT, run_review

router = APIRouter()


def _load_structured(analysis_id: str):
    path = config.safe_analysis_path(analysis_id)
    if path is None:
        return None, JSONResponse(error_payload(ErrorCode.INVALID_ANALYSIS_ID), status_code=400)
    if not path.exists():
        return None, JSONResponse(error_payload(ErrorCode.ANALYSIS_NOT_FOUND), status_code=404)
    return json.loads(path.read_text()), None


@router.get("/api/ai/prompt/{analysis_id}")
async def ai_prompt_json(analysis_id: str):
    """AI에 보내는 system + user prompt를 JSON으로 반환."""
    result, err = _load_structured(analysis_id)
    if err is not None:
        return err
    assert result is not None
    structured = result.get("structured", {})
    return JSONResponse({
        "system": SYSTEM_PROMPT,
        "prompt": build_review_prompt(structured),
    })


@router.get("/api/ai/prompt/{analysis_id}/text")
async def ai_prompt_text(analysis_id: str):
    """AI에 보내는 prompt를 평문으로 반환 (외부 웹 AI에 붙여넣기 용)."""
    result, err = _load_structured(analysis_id)
    if err is not None:
        return err
    assert result is not None
    structured = result.get("structured", {})
    text = "[SYSTEM]\n" + SYSTEM_PROMPT + "\n\n[USER]\n" + build_review_prompt(structured)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@router.post("/api/ai/review/{analysis_id}")
async def ai_review(analysis_id: str):
    """분석 결과에 대해 AI 리뷰를 실행한다."""
    path = config.safe_analysis_path(analysis_id)
    if path is None:
        return JSONResponse(error_payload(ErrorCode.INVALID_ANALYSIS_ID), status_code=400)
    if not path.exists():
        return JSONResponse(error_payload(ErrorCode.ANALYSIS_NOT_FOUND), status_code=404)

    result = json.loads(path.read_text())
    structured = result.get("structured", {})

    review_result = await run_review(structured)

    if "error" in review_result:
        payload = error_payload(ErrorCode.AI_REVIEW_FAILED, str(review_result.get("error", "")))
        return JSONResponse(payload, status_code=400)

    # 리뷰 결과를 분석 파일에 저장
    result["ai_review"] = review_result.get("review", "")
    path.write_text(json.dumps(result, ensure_ascii=False, default=str))

    return JSONResponse({"review": review_result.get("review", ""), "status": "ok"})
