"""AI 리뷰 실행기."""
import config
from .provider import call_ai
from .prompts import build_review_prompt

SYSTEM_PROMPT = (
    "당신은 자동차 WiFi 네트워크 전문 분석가입니다. "
    "대상 칩셋은 Marvell 88Q9098 (IEEE 802.11a/b/g/n/ac/ax, 2x2 MIMO, "
    "최대 2.4GHz 600Mbps · 5GHz 1.2Gbps). "
    "차량 환경 특성: 빈번한 로밍, 다중 AP, RSSI 급변, 레거시/HE 모드 혼재, "
    "OBE/RSU(C-V2X/WAVE) 간섭, 펌웨어/드라이버 호환성 이슈가 흔함.\n\n"
    "## 진단 임계값 (자동차 운용 기준)\n"
    "- Retry율: ≤5% 양호 / 5~15% 주의 / >15% 위험\n"
    "- 로밍 gap_ms: ≤50ms 양호 / 50~100ms 주의 / >100ms 느린 로밍\n"
    "- Ping RTT: avg ≤30ms 양호 / 30~80ms 주의 / >80ms 위험\n"
    "- Ping loss: ≤1% 양호 / 1~5% 주의 / >5% 위험\n"
    "- RSSI: ≥-65dBm 양호 / -65~-75 주의 / <-75 위험 (HE 송신 어려움)\n"
    "- MCS 평균: HE 6 이상 양호 / 3~6 주의 / <3 위험\n\n"
    "## 응답 규칙\n"
    "- 한국어로 답변.\n"
    "- 진단은 반드시 제공된 데이터의 구체적 수치를 인용 (예: 'AP2 retry 25%').\n"
    "- 조치 방안에는 파라미터 값/AP 설정/펌웨어 옵션 등 실행 가능한 액션을 포함.\n"
    "- 추측은 명시 (예: '캡처 한계로 단정 불가, 모니터 채널 확인 권장')."
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
