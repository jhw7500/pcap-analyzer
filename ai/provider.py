"""AI 프로바이더 — Claude API, Claude CLI(구독), OpenAI API 호출."""
import asyncio
import shutil
from typing import Optional

import httpx

async def call_ai(provider: str, api_key: str, model: str, prompt: str, system: str = "") -> str:
    """AI API를 호출하여 응답 텍스트를 반환한다."""
    if provider == "claude":
        return await _call_claude(api_key, model, prompt, system)
    elif provider == "claude_cli":
        return await _call_claude_cli(model, prompt, system)
    elif provider == "openai":
        return await _call_openai(api_key, model, prompt, system)
    else:
        return f"지원하지 않는 AI 프로바이더: {provider}"


async def _call_claude_cli(model: str, prompt: str, system: str) -> str:
    """Claude Code CLI를 spawn해 OAuth 인증된 Pro/Max 구독 세션으로 호출."""
    claude_bin = shutil.which("claude")
    if not claude_bin:
        return ("Claude CLI를 PATH에서 찾을 수 없습니다. "
                "https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/quickstart 에서 설치 후 "
                "셸에서 `claude` 실행 → `/login`으로 OAuth 인증.")

    args = [claude_bin, "-p"]
    if system:
        args += ["--append-system-prompt", system]
    if model:
        args += ["--model", model]
    # 도구 호출 차단 (단순 LLM 응답만)
    args += ["--allowedTools", ""]

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/tmp",  # 프로젝트 CLAUDE.md 자동 로드 회피
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=prompt.encode("utf-8")),
            timeout=180.0,
        )
    except asyncio.TimeoutError:
        return "Claude CLI 호출 시간 초과 (180초)"
    except Exception as e:
        return f"Claude CLI 실행 실패: {e}"

    if proc.returncode != 0:
        err = stderr.decode("utf-8", errors="ignore").strip()
        out = stdout.decode("utf-8", errors="ignore").strip()
        msg = err or out or "(빈 출력)"
        if "Not logged in" in msg or "/login" in msg:
            return "Claude CLI에 로그인되어 있지 않습니다. 서버 사용자 계정으로 `claude` 실행 후 `/login`으로 OAuth 인증."
        if "issue with the selected model" in msg or "may not exist" in msg:
            return (
                f"모델 '{model}' 사용 불가. 설정 페이지에서 다른 모델로 변경하세요. "
                "권장: claude-sonnet-4-6, claude-opus-4-7, claude-haiku-4-5. "
                f"\n(원본: {msg[:200]})"
            )
        return f"Claude CLI 오류 (exit {proc.returncode}): {msg[:400]}"

    return stdout.decode("utf-8", errors="ignore").strip() or "응답 없음"

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
