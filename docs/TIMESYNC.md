# 캡처 시각 동기화 (timesync)

여러 장비에서 따로 뜬 pcap과 로그의 시계가 어긋나 있을 때, NTP 프레임을 기준으로
어긋난 양을 측정하고 pcap 타임스탬프를 보정하는 도구.

> 웹 대시보드와는 독립적인 CLI 도구다. `scripts/timesync-*.py` 4개와
> 핵심 로직 `analyzer/core/timesync.py`로 구성된다.

## 무엇을 해결하나

한 테스트에서 장비별로 캡처를 뜨면 각자의 시계가 다르다. 실측 예(2026-07-21 캠페인):

| 캡처 장비 | NTP 서버 대비 |
|---|---:|
| DFK 무선 모니터 (ARM64 리눅스) | **+181 ~ +184초** |
| 무선 스니퍼 | +1.6 ~ +2.7초 |
| 유선 캡처 PC | −24.3초 (중간에 0으로 교정됨) |
| 장비 로그 (systemd-timesyncd) | ±0.03초 (정상) |

이 상태로 로그와 pcap을 같은 타임라인에서 보면 인과관계가 뒤집힌다. 보정 없이
병합하면 "장비가 CONNECTED를 기록한 뒤에 AP가 Assoc Response를 보낸" 것처럼 보인다.

**보정 방향은 pcap이다.** 장비 로그는 NTP로 규율되어 이미 맞아 있고, 어긋난 쪽은
캡처 장비의 시계다. 맞는 것을 틀린 쪽으로 옮기면 안 된다.

## 빠른 사용

캠페인 폴더 하나를 통째로 처리한다.

```bash
python3 scripts/timesync-batch.py tmp/20260721_CFI --out tmp/sync \
    --ssid CANTOPS_TEST --psk <WPA passphrase>
```

`sys.log`를 가진 데이터셋을 자동으로 찾아 각각 측정 → pcap 보정까지 수행한다.

```
tmp/sync/
├── TEST1/
│   ├── offset.json      측정 결과 (+ 사용한 옵션)
│   └── pcap/            NTP 타임라인으로 보정된 pcap (원본 구조 보존)
├── TEST3/ …
└── batch_summary.json
```

원본 디렉터리에는 아무것도 쓰지 않는다.

## 원리

### 오프셋은 NTP 응답 한 프레임에서 나온다

```
offset = frame.time_epoch − ntp.xmt
       = (캡처 장비 시계) − (NTP 서버 시계)
```

`ntp.xmt`는 NTP 서버가 응답을 보낸 시각으로 페이로드에 실려 있다. 서버에서
캡처지점까지는 유선 sub-ms라 이 차이는 사실상 순수 시계차다.

**`ntp.org`를 오프셋 계산에 쓰면 안 된다.** `ntp.org`는 장치가 요청을 보낸 시각인데,
장치가 무선이면 802.11 재전송·로밍 지연이 그대로 섞인다. 실측 IQR이 407 ms 대
3.8 ms로 100배 차이났다. `ntp.org`는 sys.log 이벤트와 프레임을 **짝짓는 키**로만 쓴다.

### 부호

`log_shift_seconds`는 "캡처 − NTP 서버"다. 캡처가 24.3초 뒤처져 있으면 −24.3이고,
pcap에는 **+24.3을 더해야** 맞는다. 즉 pcap 보정량은 부호를 뒤집은 값이며,
`editcap -t`가 준 값을 더하므로 그대로 넘긴다.

### 장비 IP를 가려야 한다

한 캡처에는 여러 장비(.21/.22/.23)의 NTP 교환이 거의 균등하게 섞여 있다. IP를
안 가리면 한 장비의 로그 이벤트가 남의 프레임에 붙는다. 실측에서 53건 중 4건이
오매칭됐고, 그 결과 장치 시계 검증값이 −0.29 ~ −1.00초로 정상범위(+0.001~+0.075)를
벗어났다. 도구는 매칭 표본수로 장비 IP를 자동 판별한다(`device_ip` 필드).

오프셋 자체는 목적지와 무관한 값이라 오염돼도 거의 안 변한다(0.27 ms). 망가지는
것은 **"로그를 옮길지 pcap을 옮길지"를 가르는 장치 시계 검증**이다.

## 스크립트

### 1단계 — 측정 `timesync-offset.py`

```bash
python3 scripts/timesync-offset.py <dataset> [-o 결과.json] [--ssid S --psk P]
```

| 옵션 | 설명 |
|---|---|
| `--syslog PATH` | sys.log 직접 지정. 생략 시 하위 전체를 후보로 삼는다 |
| `--pcap PATH` | 분석할 pcap (반복 지정). 생략 시 하위 자동 탐색 |
| `--ssid` / `--psk` | WPA 복호화. 암호화된 802.11 캡처는 이것 없이 NTP가 0건이다 |
| `--tz` | 로그 타임존. IANA 이름(`Asia/Seoul`) 또는 `+09:00` |
| `-o, --out` | 결과 JSON. 기본 `<dataset>/timesync_offset.json` |
| `--tolerance` | sys.log ↔ `ntp.org` 허용오차(초). 기본 1.0 |
| `--sync-pattern` | 동기화 이벤트 정규식. 기본 `Contacted time server` |
| `--tshark` / `--print-config` / `--quiet` | |

### 2단계 — pcap 보정 `timesync-shift-pcap.py` ← 기본

```bash
python3 scripts/timesync-shift-pcap.py <결과.json> --out <출력디렉터리>
```

pcap마다 자기 오프셋을 쓰므로 `--source`로 하나를 고를 필요가 없다. 한 번 돌리면
모든 캡처가 동시에 NTP 서버 타임라인으로 모인다.

| 옵션 | 설명 |
|---|---|
| `--out` | **필수.** 출력 디렉터리 |
| `--source` | 특정 pcap만 처리 (이름 부분일치) |
| `--force` | 1단계 경고를 무시하고 적용 |
| `--dry-run` | 쓰지 않고 계획만 |
| `--editcap` | editcap 경로 |

### 2단계-대안 — 로그 보정 `timesync-apply.py`

장비 시계가 틀린 데이터셋에서만 쓴다. 1단계의 `장치로그 - NTP서버` 값이 판단 근거다
— 수십 ms면 pcap을, 초 단위로 벌어져 있으면 로그를 봐야 한다.

```bash
python3 scripts/timesync-apply.py <로그디렉터리> --config <결과.json> \
    --source <pcap이름> --out <출력디렉터리>

# 오프셋을 이미 알고 있으면 1단계 없이 직접 줘도 된다
python3 scripts/timesync-apply.py <로그디렉터리> --offset -24.3173 --out <출력디렉터리>
```

지원 타임스탬프 포맷 (모두 줄 시작 앵커):

```
2026-07-21 14:57:01.205 ...       cpu, kern, logger, summary, sys, wpa.log + DFK AP logfile
[2026-07-21 14:57:02] ...         ap, freq, stat.log
===== 2026-07-21 14:57:04 =====   snap.log
```

소수 자릿수는 보존하고, 소수 없는 포맷은 가장 가까운 초로 반올림한다. 본문 속
날짜(AP 로그의 `NTP: Setting clock (2015-01-01 00:00:07)` 같은)는 건드리지 않는다.
CRLF와 비UTF-8 바이트도 바이트 단위로 보존된다. 포맷이 다르면
`--pattern '^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)'` 식으로 추가한다.

### 일괄 — `timesync-batch.py`

```bash
python3 scripts/timesync-batch.py <루트> --out <출력루트> [--skip-existing]
```

| 옵션 | 설명 |
|---|---|
| `--out` | **필수.** 출력 루트 |
| `--skip-existing` | 중단 후 재개 — `offset.json`이 있으면 측정만 건너뛰고 **보정은 이어서** 한다. 보정본까지 다 있으면 그 데이터셋 전체를 건너뛴다 |
| `--measure-only` | 측정만, pcap 보정 안 함 |
| `--dry-run` | 대상만 나열 |

## 설정 파일

반복 옵션은 JSON에 담는다. **우선순위: CLI 인자 > 설정 파일 > 내장 기본값**

```bash
python3 scripts/timesync-offset.py <dataset> --print-config > timesync.json
```

```jsonc
{
  "timesync": {
    "ssid": "CANTOPS_TEST",
    "psk": "...",
    "tz": "Asia/Seoul",
    "tolerance": 1.0,
    "source": "FXE3000",
    "glob": ["*.log"]
  }
}
```

`--config` 생략 시 자동 탐색한다:

- 1단계: `<dataset>/timesync.json` → `<dataset>/../timesync.json` → `./timesync.json`
- 2단계: `<logdir>/timesync.json` → **`<logdir>/../timesync.json`** → `./timesync.json`

2단계가 부모까지 보므로 데이터셋 루트에 하나만 두면 두 단계가 같이 집는다.
끄려면 `--no-config`.

**1단계 결과 JSON을 그대로 `--config`로 넘길 수 있다** — 옵션(`options` 블록)과
오프셋(`sources`)이 한 파일에 있어 2단계가 `--offset-file` 없이 동작한다.
PSK는 결과 JSON에 저장하지 않는다(2단계가 쓰지 않으므로 손실 없음).

## 결과 읽는 법

```
--- .../유선/FXE3000_1번테스트_1515.pcapng ---
    NTP mode4 프레임 : 51
    sys.log 매칭     : 43/44  (1호기)
    매칭 잔차        : median=+0.429809s   ← 왕복시간+로깅지연. 0.4초 안팎이 정상
    캡처 - NTP서버   : median=-24.317308s  IQR=0.003137s  n=43
    장치로그 - NTP서버: median=+0.031530s  (상한)
    드리프트         : +5.93 ppm
    => log_shift     : -24.317308 s
```

**`캡처 - NTP서버`** 가 보정할 값이다. IQR이 수 ms면 신뢰할 만하다.

**`장치로그 - NTP서버`** 는 장비 시계가 NTP에 맞아 있는지 보는 지표다.
편도지연·로깅지연이 더해져 있어 상한이며, **음수면 그만큼 확실히 뒤처졌다는
하드 바운드**다. 수십 ms면 정상(로깅 지연), 초 단위면 로그 쪽을 의심해야 한다.

### `method` — 산출 방식

| 값 | 의미 |
|---|---|
| `syslog-matched` | sys.log와 짝지은 프레임만 사용. 장치 시계 검증 가능 |
| `ntp-only` | 대응 sys.log 구간이 없어 NTP 프레임 전체로 산출 |

`ntp-only`도 오프셋은 정확하다. 같은 캡처에서 대조한 결과 `syslog-matched`
−24.309579s 대 전체 −24.309565s로 **14 마이크로초** 차이였다. 다만 장치 시계
검증을 못 하므로 **로그 보정 기준으로는 쓰지 않는다**(`timesync-apply.py`가 거부).

### 경고 3단계

영향 범위로 나뉜다.

| 표기 | 필드 | pcap 보정 | 로그 보정 |
|---|---|:---:|:---:|
| `[!]` | `warnings` | 차단 | 차단 |
| `[!로그전용]` | `log_warnings` | 통과 | 차단 |
| `[i]` | `notes` | 통과 | 통과 |

`warnings`는 오프셋 값 자체를 못 믿는 경우(표본 부족 등)다. 장치 시계 지연은
`log_warnings`로 간다 — pcap을 NTP 서버에 맞추는 데 장치 시계는 무관하기 때문이다.

## 안전장치

원본은 절대 수정하지 않는다. 다음은 모두 exit 2로 거부된다.

| 메시지 | 원인 |
|---|---|
| `--out 과 입력 트리가 겹친다` | 출력이 입력의 안이면 이중 보정, 위면 형제 원본 덮어쓰기 |
| `출력 경로가 --out 밖으로 나가는 대상이 N개` | `--glob`에 `..`이 있음. 쓰기 **전에** 전수 검사한다 |
| `출력 경로가 겹치는 pcap 이 있다` | 데이터셋 밖 pcap은 파일명으로만 구분된다. 이름이 같으면 뒤엣것이 앞엣것을 덮어쓰므로 미리 막는다 |
| `1단계가 이 오프셋을 그대로 쓰지 말라고 경고했다` | 확인 후 `--force` |
| `정규식에 (?P<ts>...) 그룹이 없다` | `--pattern` 형식 오류 |
| `설정 파일에 알 수 없는 키` | 오타. 사용 가능한 키를 함께 출력 |

**종료 코드**: `0` 성공 / `1` 산출·변경 없음 / `2` 사용법·환경 오류

### PSK는 프로세스 목록에 보인다

`--psk`는 tshark의 복호화 옵션(`uat:80211_keys`)으로 그대로 넘어간다. 인자를 리스트로
넘기므로 셸 인젝션은 없지만, 실행 중에는 `ps aux`와 `/proc/<pid>/cmdline`에 평문으로
노출된다. tshark CLI의 구조적 한계라 우회할 방법이 없다.

**공유 서버에서는 다른 사용자가 볼 수 있다.** 결과 JSON에는 `psk`가 `null`로 기록되니
산출물 유출 걱정은 없지만, 실행 환경 자체는 신뢰할 수 있는 곳이어야 한다.

## 검증

보정된 pcap을 1단계에 다시 넣으면 잔차가 0에 수렴해야 한다.

```bash
args=$(find <출력>/pcap -type f | sed 's/^/--pcap /' | tr '\n' ' ')
python3 scripts/timesync-offset.py <원본dataset> --no-config --quiet \
    --ssid S --psk P $args -o /tmp/verify.json
```

3개 캠페인 18개 데이터셋 85개 pcap에서 **잔차 최대 1 마이크로초**를 확인했다.

## 트러블슈팅

| 증상 | 원인/해결 |
|---|---|
| `결과를 쓸 수 없다 (Permission denied)` | 데이터셋이 root 소유. `-o /tmp/…`로 다른 경로 지정하거나 `sudo chown -R $USER:$USER <dir>` |
| `sys.log 매칭 0건` (전 pcap) | ① 타임존 불일치 → `--tz Asia/Seoul`. `TZ=UTC`에서 돌리면 전량 0건이 된다 ② 로그와 캡처가 다른 시간대. 이 경우 `ntp-only`로 자동 폴백된다 |
| `NTP mode 4 프레임 0건` | ① 암호화 캡처인데 `--ssid/--psk` 누락 ② ICMP만 추출한 파일 ③ 빈 파일(`capinfos`로 패킷 수 확인) |
| 다중 장비 데이터셋에서 이상한 로그를 집음 | 1·2·3호기 로그가 있으면 pcap별로 가장 잘 맞는 것을 자동 선택한다. 출력의 `(2호기)` 표기로 확인. 강제하려면 `--syslog` |
| `pcap 이 damaged or corrupt` | 캡처 끝 블록이 잘린 것. 읽힌 프레임은 정상이고 editcap이 종료코드 0으로 복구한다. `[i]` 정보로만 표시되며 보정을 막지 않는다 |
| 같은 장비의 연속 파일에 ms 단위 이음매 | 파일마다 자기 오프셋을 쓰기 때문(드리프트). 20분 캡처에서 8 ms 수준이라 초 단위 정렬에는 무해하다. 통일하려면 `--source`로 하나만 골라 같은 값을 적용 |
| 소스별 오프셋이 크게 벌어짐 | 정상이다. 캡처 장비마다 시계가 다르다. pcap 보정은 각자 값을 쓰므로 고를 필요 없고, 로그 보정에서만 `--source`가 필요하다 |

## 의존성

- `tshark` — NTP 프레임 추출 (WPA 복호화 포함)
- `editcap` — pcap 타임스탬프 이동

둘 다 Wireshark 패키지에 포함된다. `--tshark` / `--editcap`으로 경로 지정 가능하며,
`tshark`는 PATH에 없으면 `config.detect_tshark()`로 폴백한다(Windows 기본 설치 경로 포함).

## 테스트

```bash
python3 -m pytest tests/test_timesync.py -q
```
