"""AI 프로바이더 — Claude, OpenAI API 호출."""
import httpx
from typing import Optional

async def call_ai(provider: str, api_key: str, model: str, prompt: str, system: str = "") -> str:
    """AI API를 호출하여 응답 텍스트를 반환한다."""
    if provider == "claude":
        return await _call_claude(api_key, model, prompt, system)
    elif provider == "openai":
        return await _call_openai(api_key, model, prompt, system)
    else:
        return f"지원하지 않는 AI 프로바이더: {provider}"

async def _call_claude(api_key: str, model: str, prompt: str, system: str) -> str:
    model = model or "claude-sonnet-4-6"
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 4096,
                "system": system or "You are a WiFi network analysis expert.",
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        if resp.status_code != 200:
            return f"AI API 오류 ({resp.status_code}): {resp.text[:200]}"
        data = resp.json()
        return data.get("content", [{}])[0].get("text", "응답 없음")

async def _call_openai(api_key: str, model: str, prompt: str, system: str) -> str:
    model = model or "gpt-4o"
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system or "You are a WiFi network analysis expert."},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 4096,
            },
        )
        if resp.status_code != 200:
            return f"AI API 오류 ({resp.status_code}): {resp.text[:200]}"
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "응답 없음")
