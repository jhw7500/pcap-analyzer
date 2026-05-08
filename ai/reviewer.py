"""AI 리뷰 실행기."""
import config
from .provider import call_ai
from .prompts import build_review_prompt

SYSTEM_PROMPT = (
    "당신은 자동차 WiFi 네트워크(802.11, 88Q9098 칩셋) 전문 분석가입니다. "
    "WLAN pcap 분석 결과를 검토하고 실질적인 네트워크 진단과 조치 방안을 제시합니다. "
    "한국어로 답변하세요. 구체적인 수치와 파라미터 값을 포함하세요."
)

async def run_review(structured: dict) -> dict:
    """AI 리뷰를 실행하고 결과를 반환한다."""
    provider = config.get("ai_provider")
    api_key = config.get("ai_api_key")
    model = config.get("ai_model")

    if not provider:
        return {"error": "AI 설정이 없습니다. 설정 페이지에서 프로바이더를 선택하세요."}
    # claude_cli는 OAuth 기반이라 API 키 불필요
    if provider != "claude_cli" and not api_key:
        return {"error": "API 키가 없습니다. 설정 페이지에서 입력하세요."}

    prompt = build_review_prompt(structured)
    response = await call_ai(provider, api_key, model, prompt, SYSTEM_PROMPT)
    return {"review": response, "prompt_used": prompt}
