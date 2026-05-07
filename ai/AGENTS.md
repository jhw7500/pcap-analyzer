<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-09 -->

# ai

## Purpose
분석 결과를 AI(Claude/OpenAI)에 보내 네트워크 진단 리뷰를 받는 모듈. 구조화된 분석 데이터를 요약 프롬프트로 변환하고, API를 호출하여 문제점/원인/조치방안을 생성한다.

## Key Files

| File | Description |
|------|-------------|
| `reviewer.py` | 리뷰 실행기 — config에서 프로바이더/키/모델 읽기, 프롬프트 빌드 후 API 호출 |
| `prompts.py` | 분석 결과를 4000토큰 이내 프롬프트로 변환. 개요/로밍/Ping/신호/지연/이상 요약 포함 |
| `provider.py` | AI API 호출 — Claude (Anthropic Messages API), OpenAI (Chat Completions) 지원 |

## For AI Agents

### Working In This Directory
- 시스템 프롬프트는 자동차 WiFi(802.11, 88Q9098 칩셋) 전문 분석가 역할로 설정됨.
- API 키는 `config.local.json`의 `ai_api_key` 또는 `PCAP_AI_API_KEY` 환경변수.
- 새 AI 프로바이더 추가 시: `provider.py`에 `_call_{provider}()` 함수 추가 → `call_ai()`의 분기에 등록.

### Common Patterns
- `build_review_prompt()`는 구조화 데이터에서 핵심 지표만 추출하여 토큰 효율적인 프롬프트 생성.
- 모든 API 호출은 `httpx.AsyncClient`로 비동기 처리. 타임아웃 120초.

## Dependencies

### Internal
- `config` — AI 프로바이더, API 키, 모델 설정 조회

### External
- `httpx` — 비동기 HTTP 클라이언트

<!-- MANUAL: -->
