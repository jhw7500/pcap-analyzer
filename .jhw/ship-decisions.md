# PR #29 라운드 4 (04a87ee) — 전원 CLEAN

- **Claude Code Review**: run success. 본문 명시 **"MEDIUM 이상 차단 이슈 없음"**.
  [LOW]×3 → 보고만(블로킹 미만). ① report/prompts에서 basis를 원시 문자열로 비교
  ② charts.js `LOSS_BASIS_LABEL` 맵 중복 ③ exping docstring 흐름 단절.
- **Gemini Auto PR Review**: run success. [MEDIUM]×2 + [LOW]×1, **HIGH 없음** → CLEAN.
  - [MEDIUM] `charts.js` escapeHtml 미정의 위험 → **반려**. IIFE 최상단(8행) `const`
    정의, 사용은 2021행 같은 스코프. 정의가 먼저 실행되므로 TDZ 아님(실측 확인).
  - [MEDIUM] `wired_ping` warnings_out 계약 의존 → **이미 반영**(3R에서 전용 리스트
    분리 + 가짜 tshark 동작 테스트 `TestWarningsOutContract` 4건으로 계약 고정).
  - [LOW] `_loss_for_judgment` 타입 체크 → 보고만.
- **Codex(앱)**: 마지막 신호는 `1da1f6f`의 **P2 1건**(부분 추출 GT 승격) — 1R에서
  반영 완료. 이후 신규 없음. Codex는 push로 재트리거되지 않으므로(`@codex review`
  코멘트가 트리거) PENDING이 아니라 **CLEAN**.
- **Gemini Assist(앱)**: 이 리포에 신호 이력 없음 → expected 집합에서 제외.

**판정: 전원 CLEAN(블로킹 0건) → 머지 게이트 충족.** `--merge`는 옵트인이라 대기.

# PR #29 라운드 1~3 — 반영/반려 기록

## 반영 (블로킹)
- [P1급 성격][Codex P2] 부분 추출 GT를 1차 판정으로 승격 → `extraction_partial`
  플래그 신설(`wired_ping`)로 차단. 실측: 정상 캡처에서 False 확인.

## 반영 (비블로킹이나 실제 결함이라 수용)
- [Claude MEDIUM] `(None, "wireless_observed")` 모순 — `.get(k, 0)`이 값 None이면
  None을 주는 함정. 값-근거 짝 불변식을 테스트로 고정.
- [Claude MEDIUM] 무선 근거 없을 때 이슈 드롭이 **테스트로 검증되지 않음** — 픽스처에
  근거 필드(req_num/epoch)가 없어 이슈가 항상 드롭돼 단언이 무의미하게 통과했다.
  대조군 테스트 추가로 드롭이 조건부임을 증명.
- [Claude LOW + Gemini MEDIUM] `bool(warnings)` 순서 계약 취약 → 전용 리스트로 격리.
- [Gemini MEDIUM] AI 프롬프트에 두 손실률 관계 명시(구버전 폴백 포함).
- [Claude MEDIUM] `total` 타입 완화, [Claude LOW] `bool` 서브클래스 배제.

## 반려 (근거와 함께 — 재등장해도 재차단하지 않음)
- [Claude MEDIUM×4회] `attach_station_to_sequences` 방어적 복사 →
  **얕은 복사여도 기능이 깨진다.** 그 dict들이 곧 `structured["roaming"]["sequences"]`
  라 복사본에 붙이면 `sta_log`가 결과에 실리지 않는다. in-place가 load-bearing.
- [Gemini MEDIUM] 무선 근거 없이도 Ping Loss 이슈 리스트업 →
  **"근거 없는 결론 0건"이 저장소 대원칙**이고 `_add_net_issue`가 강제한다.
  유선 확정 손실 상세는 `_ground_truth_issue_candidates`가 streak별로 낸다.
- [Gemini LOW] UI `toFixed(2)` → 서버가 이미 `round(..., 2)`한 값. 표시 계층에서
  다시 포맷하면 정수 0%가 "0.00%"로 바뀌는 등 표기만 흔들린다.

# PR #28 (머지 완료, 5a3acba) — 회고

**스킬 미적용 사례.** 블로킹은 Codex P1 2건(STA 로그 TZ, mergecap 이벤트루프)과
Gemini HIGH 1건(mergecap 의존성 문서화)뿐이었다. 심각도 게이트를 적용했다면
**2라운드에 CLEAN 종료**였는데, P2/MEDIUM/LOW를 블로킹처럼 다뤄 **5라운드**를 돌았다.

초과 라운드가 무가치하진 않았다(cliff 2배 부풀림 자체 발견, 스캔 페어링 기준 오류,
`_LOG_SKIP` 미사용). 다만 종료 조건을 감으로 정한 것이 문제다 — 스킬의 심각도
게이트와 결정 추적이 있으면 같은 지적을 5라운드 반복 응답할 이유가 없다.

## 반려 (PR #28에서 확정 — 재등장 시 재차단 금지)
- [Gemini HIGH×5회] mergecap 외부 의존성/경로 화이트리스트 → README에 의존성·영향
  범위 명시로 **반영 종결**. 경로는 서버가 만든 tempfile이고 셸을 거치지 않는다.
- [Claude MEDIUM×3회] `_result_cache` 깊은 복사 → 33MB × 요청마다는 캐시 목적 자체를
  무산시킨다. 계약 위반 감지 테스트로 대체(Claude가 제안한 대안).
- [Claude LOW×3회] `_RESULT_CACHE_MAX` 상향 → 같은 분석의 여러 엔드포인트는 같은
  파일이라 2로 충분. 33MB × n이 곧 메모리 비용.
- [Gemini MEDIUM] `_save_station_logs` 미소비 UploadFile 스트림 → Starlette가 요청
  종료 시 정리. 거부 경로에서 남은 파일을 다 읽는 건 낭비.
- [Gemini LOW] `collect_station_files` `is_dir()` 선행 체크 → `Path.is_file()`이 이미
  OSError를 흡수해 False를 준다.
- [Gemini MEDIUM] `classify_slow` 판정 불가가 건강도 오염 → **이미 처리됨**
  (`measurable_roams`가 분모에서 제외). Gemini가 diff 절단으로 못 본 코드.
