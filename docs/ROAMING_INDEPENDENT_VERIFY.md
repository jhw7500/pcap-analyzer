# 독립 로밍 검증 CLI

`scripts/roaming_independent_verify.py`는 웹 분석기의 로밍 결과를 **별도 구현으로
교차 검증**한다. 분석기의 `analyzer` 패키지를 import하지 않으며 다음 원본만 읽는다.

- 무선 pcap/pcapng: `tshark`로 Auth, Assoc/Reassoc, EAPOL, Beacon TSF 필드 전수 추출
- STA `wpa.log`: `ROAM` 명령부터 `CTRL-EVENT-CONNECTED` 또는 실패까지 직접 파싱
- 분석기 결과 JSON: 모든 독립 계산을 끝낸 뒤 비교할 때만 선택적으로 읽음

따라서 분석기 내부 함수나 structured 생성 로직을 재사용하는 자기검증이 아니다.

## 검증 절차

1. 관측점별 관련 패킷을 누락 없이 추출한다.
2. 공통 `(BSSID, Beacon TSF)`의 중앙값으로 관측점 시각을 정렬한다.
3. 시퀀스·subtype·retry를 기준으로 관측점 간 같은 프레임만 제거한다.
4. Auth부터 Assoc/Reassoc까지 독립 로밍 거래 원장을 만든다. 새 Auth가 없는 동일
   STA→AP/subtype의 1초 이내 반복은 하나의 연결 시도로 묶는다.
5. STA 로그별 로밍 원장을 만들고 AP·시간 잔차로 STA MAC과 자동 바인딩한다.
6. STA 체감시간을 우선하여 150ms 초과를 느린 로밍으로 판정하고, STA 로그가 없는
   거래만 pcap 100ms 기준으로 보완한다.
7. `--analyzer-result`가 있으면 총건수·느림·판정 가능·STA 부착과 개별 이벤트를
   비교한다. `--strict`에서는 불일치 시 종료 코드 2를 반환한다.

> 이 도구의 "전수"는 pcap 전체에서 로밍 판정에 필요한 관리/EAPOL/Beacon 프레임을
> 필터로 전부 읽는다는 뜻이다. 데이터·제어 프레임 전체를 JSON에 복제하지는 않는다.

## 사용법

```bash
python3 scripts/roaming_independent_verify.py \
  --source primary=/path/main-1.pcapng \
  --source primary=/path/main-2.pcapng \
  --source dfk=/path/dfk-1.pcap \
  --source dfk=/path/dfk-2.pcap \
  --station car1=/path/car1/wpa.log \
  --station car2=/path/car2/wpa.log \
  --reference primary \
  --analyzer-result /path/analyzer-result.json \
  --output /path/independent-result.json \
  --markdown /path/independent-result.md \
  --strict
```

- 같은 `--source TAG=...`를 반복하면 시간순 분할 캡처로 취급한다. 미리 `mergecap`할
  필요가 없다.
- `--reference`는 시간 기준으로 삼을 관측점 TAG다. 생략하면 첫 source가 기준이다.
- `wpa.log` 시각은 호스트 시간대와 무관하게 기본 `+09:00`(KST)로 해석한다. 다른
  지역 로그는 `--station-utc-offset=-05:00`처럼 명시한다.
- 자동 STA 바인딩이 불가능한 특수 캡처는 `--bind car1=00:11:22:33:44:55`처럼
  명시할 수 있다.
- 분석기 결과가 없어도 독립 원장 생성은 가능하다. 비교만 생략된다.
- 기본 출력은 JSON이며 `--markdown`을 생략하면 JSON과 같은 이름의 `.md`도 만든다.
- 메모리 고갈을 막기 위해 전체 source 합계 기준 로밍/EAPOL 행은 기본 200,000건,
  고유 Beacon `(BSSID, TSF)` 키는 기본 500,000건에서 중단한다. CLI에서는
  `--max-event-rows`, `--max-beacon-keys`로 조정할 수 있고 적용값은 결과 JSON의
  `independence.memory_limits`에 기록된다.

종료 코드는 성공 0, 입력·tshark·정렬 실패 1, `--strict` 비교 불일치 2다.

## 웹에서 실행

1. 메인 화면에서 무선 pcap과 필요하면 추가 스니퍼·STA 로그를 선택한다.
2. **분석 옵션**의 **독립 로밍 교차검증 실행**을 체크한다.
3. 분석을 시작한다. 본 분석이 끝난 뒤 같은 임시 원본으로 독립 검증이 이어진다.
4. 결과 화면 상단의 교차검증 패널에서 일치 여부와 주요 수치를 확인한다.
5. **검증 JSON** 또는 **검증 Markdown**으로 원장을 내려받을 수 있다.

웹 실행은 명시적 opt-in이다. 체크하지 않으면 추가 tshark 실행이나 처리 시간 변화가
없다. 원본 업로드는 보안·용량상 분석 후 삭제되므로 **기존 분석 결과에 사후 실행은
불가능**하며 새로 업로드해야 한다. 또한 원본 전체와 분석기 결과를 같은 범위에서
대조하기 위해 MAC/IP/시작·종료 시간 필터와 동시 사용은 차단한다.

웹 서버에서는 독립 검증을 프로세스당 한 건씩 실행한다. 대기 중인 분석도 취소할 수
있으며, 프레임 상한을 넘으면 본 분석은 보존한 채 독립 검증만 실패로 표시한다.

독립 검증이 실패해도 이미 완료된 본 분석 결과는 폐기하지 않는다. 결과 화면에 실패
사유를 표시하며, 공통 Beacon TSF가 없는 다중 스니퍼 입력이나 STA 로그 매핑 실패를
확인할 수 있다.

## TEST14 기준 결과

2026-08-12에 `tmp/20260723_CFI/TEST14`의 주 무선 3조각, DFK 7조각, 1~3호기
`wpa.log`를 입력하여 확인했다.

| 항목 | 독립 검증 결과 |
|---|---:|
| 패킷 로밍 거래 | 882 |
| STA 로그 명령 | 884 (성공 883, 실패 1) |
| PCAP↔STA 매칭 | 880 |
| 느린 로밍(>150ms) | 12 |
| 판정 가능 / 불가 | 882 / 0 |
| STA 체감 p50 / p95 | 111ms / 139ms |

수정 후 표적 분석 결과 `tmp/test14_validation/fix-validation.json`과 요약값이 모두
일치했다. 반대로 수정 전 전체 결과에는 분석기 전용 이벤트 2건이 남아 총 884건,
판정 불가 2건으로 보고되었고, 독립 비교기가 이 차이를 검출했다. 즉 현재 결과 일치뿐
아니라 발견했던 중복 계수 회귀도 실제 데이터에서 탐지할 수 있다.

재현 산출물(로컬, git 제외):

- `tmp/test14_validation/independent-result.json`
- `tmp/test14_validation/independent-result.md`
- `tmp/test14_validation/web-independent-result.json` (웹 어댑터 경로)

## 한계

- 서로 다른 관측점에 공통 Beacon TSF가 없으면 임의 시각 정렬을 하지 않고 실패한다.
- STA 로그 자동 바인딩은 대상 AP와 시간 패턴이 구분되어야 한다. 모호하면 `--bind`를
  사용한다.
- EAPOL msg4가 암호화·캡처 누락으로 보이지 않으면 STA 로그가 없는 거래의 pcap 전체
  시간은 판정 불가일 수 있다.
- 판정 임계값은 현재 제품 정책과 같은 STA 150ms, pcap 100ms다. 독립 구현이지만 비교
  정책 자체는 의도적으로 동일하다.
