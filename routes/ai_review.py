"""AI 리뷰 API."""
import json
from fastapi import APIRouter
from fastapi.responses import JSONResponse

import config
from ai.reviewer import run_review

router = APIRouter()


@router.post("/api/ai/review/{analysis_id}")
async def ai_review(analysis_id: str):
    """분석 결과에 대해 AI 리뷰를 실행한다."""
    path = config.safe_analysis_path(analysis_id)
    if path is None:
        return JSONResponse({"error": "invalid analysis id"}, status_code=400)
    if not path.exists():
        return JSONResponse({"error": "분석 결과를 찾을 수 없습니다."}, status_code=404)

    result = json.loads(path.read_text())
    structured = result.get("structured", {})

    review_result = await run_review(structured)

    if "error" in review_result:
        return JSONResponse(review_result, status_code=400)

    # 리뷰 결과를 분석 파일에 저장
    result["ai_review"] = review_result.get("review", "")
    path.write_text(json.dumps(result, ensure_ascii=False, default=str))

    return JSONResponse({"review": review_result.get("review", ""), "status": "ok"})
