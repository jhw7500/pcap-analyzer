<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# templates

## Purpose
Jinja2 HTML 템플릿. TailwindCSS + Plotly.js 기반의 다크 테마 대시보드 UI. CDN/로컬 vendor를 설정으로 전환 가능.

## Key Files

| File | Description |
|------|-------------|
| `base.html` | 공통 레이아웃 — `<head>`에서 `{% if offline_assets %}` 분기로 CDN 또는 `/static/vendor/`(Tailwind, Plotly) 로드. 네비게이션 바, `{% block content %}`. |
| `index.html` | 대시보드 메인 — pcap 업로드 폼 (드래그앤드롭), WPA/필터 옵션, 이전 분석 목록, 진행률 표시 |
| `analysis.html` | 분석 결과 페이지 — 탭 기반 (Overview, 타임라인, 로밍, Ping, 장치별, 종합진단), AI 리뷰 버튼 |
| `settings.html` | 설정 페이지 — tshark 경로, AI 프로바이더/모델, UI 오프라인 에셋 토글. API 키는 `type=password` + `value=""`(재노출 금지) + placeholder에 마스킹된 힌트만 표시. |

## For AI Agents

### Working In This Directory
- 모든 템플릿은 `base.html`을 상속 (`{% extends "base.html" %}`).
- `analysis.html`은 `result_json` 변수로 구조화 데이터를 JS에 전달 (`DATA = {{ result_json|safe }}`).
- 탭 전환은 `static/js/charts.js`에서 처리.
- 차트 렌더링 로직은 `static/js/` 쪽에 분리되어 있으므로 템플릿에는 `<div id="chart-*">` 컨테이너만 존재.
- 모든 route의 `TemplateResponse` context에 `offline_assets=config.is_offline_assets()`를 전달해야 `base.html`의 에셋 분기가 동작. 누락 시 기본 CDN 분기로 폴백.

### Common Patterns
- TailwindCSS 유틸리티 클래스 직접 사용 (별도 CSS 최소화).
- 다크 테마: `bg-gray-900`, `text-gray-100`, `bg-gray-800` 카드.
- 한국어 UI 텍스트.
- 민감값(API 키 등)은 `value=""`로 두고 placeholder에 마스킹된 힌트만(`저장됨 (****xxxx5)`).

## Dependencies

### External
- TailwindCSS 3.x (CDN 또는 `/static/vendor/tailwind.js`)
- Plotly.js 2.32 (CDN 또는 `/static/vendor/plotly.min.js`)
- `make fetch-vendor`로 로컬 다운로드 + `ui_offline_assets=true` 설정으로 전환

<!-- MANUAL: -->
