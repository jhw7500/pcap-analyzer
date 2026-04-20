<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# js

## Purpose
프론트엔드 JavaScript. Plotly.js로 차트 렌더링, pcap 업로드/진행률 UI, 통합 타임라인 시각화를 담당한다.

> 업로드 흐름은 하위호환 `/api/progress` + `/api/cancel` 폴링 엔드포인트를 사용한다. 서버 내부는 job id 기반으로 분석 상태를 추적하지만 프론트는 "가장 최근 active job" 반환을 그대로 받아 처리한다.

## Key Files

| File | Description |
|------|-------------|
| `charts.js` | 분석 결과 차트 렌더링 — Overview(프로토콜/서브타입 분포), 로밍 갭 차트, 장치별 통계. 탭 전환 로직 포함. 전역 `DATA` 객체에서 데이터 소비. |
| `upload.js` | pcap 업로드 UI — 드래그앤드롭, 파일 선택, FormData 전송, `/api/progress` polling으로 진행률 표시, 취소 버튼. |
| `timeline.js` | 통합 타임라인 — RSSI + Retry + Ping RTT 동기화 서브플롯. LTTB 다운샘플링으로 대량 데이터 렌더링 최적화. 로밍 이벤트 annotation 표시. |

## For AI Agents

### Working In This Directory
- 모든 JS 파일은 IIFE `(function() { ... })()` 패턴으로 격리.
- `DATA` 전역 변수는 `analysis.html` 템플릿에서 `{{ result_json|safe }}`로 주입.
- Plotly.js 차트 설정은 `DARK` 상수로 다크 테마 통일.
- `COLORS` 배열로 일관된 색상 팔레트 사용.

### Common Patterns
- `Plotly.newPlot(elementId, traces, layout, config)` 패턴.
- 대량 데이터는 LTTB(Largest Triangle Three Buckets) 다운샘플링 적용.
- Plotly layout: `paper_bgcolor: 'rgba(0,0,0,0)'`, `plot_bgcolor: 'rgba(0,0,0,0)'` (투명 배경).

## Dependencies

### External
- Plotly.js 2.32 — `base.html`의 `{% if offline_assets %}` 분기로 CDN 또는 `/static/vendor/plotly.min.js` 로드

<!-- MANUAL: -->
