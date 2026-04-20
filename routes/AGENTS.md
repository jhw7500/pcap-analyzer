<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# routes

## Purpose
FastAPI 라우트 핸들러. pcap 업로드/분석 실행(스트리밍 + magic byte 검증), 분석 결과 조회/삭제(path traversal 방어), AI 리뷰 요청, 설정 페이지를 담당한다.

## Key Files

| File | Description |
|------|-------------|
| `upload.py` | pcap 업로드(1MB 청크 스트리밍 + magic byte) + 분석 실행. `_jobs` dict로 job id별 상태 추적. 엔드포인트: `/api/progress/{job_id}`, `/api/cancel/{job_id}` 및 하위호환 `/api/progress`, `/api/cancel`. 최근 100개 job만 유지. |
| `analysis.py` | 분석 결과 HTML 렌더링, JSON/텍스트 내보내기, 삭제 API. 모든 `analysis_id`는 `config.safe_analysis_path()`로 검증. |
| `ai_review.py` | AI 리뷰 요청 API — 분석 결과를 AI에 보내고 리뷰를 JSON에 저장. id 검증 + 에러 카탈로그 사용. |
| `settings.py` | 설정 페이지 (tshark 경로, AI 프로바이더/키/모델, `ui_offline_assets` 오프라인 에셋 옵션). API 키 평문 재노출 금지(placeholder 마스킹만). |

## For AI Agents

### Working In This Directory
- 모든 라우터는 `app.py`에서 `include_router()`로 등록.
- `upload.py`의 분석은 `asyncio.run_in_executor`로 백그라운드 스레드에서 실행. `threading.Event`가 tshark 프로세스 kill까지 전파됨.
- 분석 결과 JSON은 `data/analyses/{id}.json`에 저장. 조회/삭제 시 반드시 `config.safe_analysis_path(id)`로 경로 검증.
- 파일 업로드: `_UPLOAD_CHUNK_SIZE=1MB` 스트리밍, 상한 `config.MAX_UPLOAD_SIZE`(200MB), 확장자 + 첫 청크 magic byte 검증.
- 에러 응답은 `analyzer.errors.error_payload(ErrorCode.XXX)`로 `{error, code, hint}` 3필드 반환. 하드코딩 금지.

### Common Patterns
- `Jinja2Templates(directory="templates")` — 각 라우트에서 독립 인스턴스, TemplateResponse context에 `offline_assets=config.is_offline_assets()` 전달.
- JSON 응답은 `JSONResponse`, HTML은 `templates.TemplateResponse`.
- Job id별 상태: `_jobs[job_id] = {msg, pct, active, created, cancel, tmp}`.

## Dependencies

### Internal
- `config` — 설정, tshark 감지, `safe_analysis_path()`, `mask_secret()`, `is_offline_assets()`
- `analyzer.pipeline.run_analysis` — pcap 분석 실행
- `analyzer.core.pcap_magic.has_valid_pcap_magic` — 업로드 첫 청크 검증
- `analyzer.errors` — ErrorCode + error_payload
- `ai.reviewer.run_review` — AI 리뷰 실행

<!-- MANUAL: -->
