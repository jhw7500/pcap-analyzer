# EXPING 로그 도구 (exping)

EXPING 은 시험에 쓰는 일본산 Windows ping 도구다. 6열 CSV 를 뽑고 사용자는 그것을
엑셀로 열어 xlsx 로 보관한다. 이 문서는 그 형식을 다루는 두 CLI 도구를 설명한다.

> 웹 대시보드와는 독립적인 CLI 도구다. `scripts/exping-*.py` 2개와 핵심 로직
> `analyzer/core/exping.py` 로 구성된다. xlsx 출력에만 openpyxl 이 필요하다
> (`pip install -r requirements-exping.txt`).

## 무엇을 해결하나

| 상황 | 쓸 도구 |
|---|---|
| EXPING 로그가 온전한데 xlsx 만 없다 | `exping-csv-to-xlsx.py` — **무손실 변환** |
| 로그가 잘렸거나, 시계가 어긋났거나, 아예 없다 | `exping-from-pcap.py` — pcap 에서 재구성 |

> 웹 대시보드도 같은 매칭 규칙을 재사용한다 — 업로드 폼에 유선 pcap을 함께
> 넣으면 `analyzer/core/wired_ping.py`가 ground truth를 계산한다.

실측 사례. 2026-07-21 캠페인은 테스트 9개 전부 EXPING 로그가 **마지막 1,000행(약 2분)만**
남아 있었고, 그나마 로그 시계가 보정 pcap 대비 **41초** 어긋나 있었다. 20분짜리 시험의
앞 18분이 통째로 없는 셈이라 로밍 이벤트와 대조할 수가 없다. 반면 07-22·07-23 캠페인은
로그가 전체본이라 재구성할 이유가 없고, 없는 것은 xlsx 뿐이었다.

**원본 로그가 온전하면 재구성하지 마라.** 재구성은 왕복시간 정수 ms 를 95% 만 맞히고,
`Destination host unreachable` 같은 값은 애초에 만들어낼 수 없다.

## 빠른 사용

```bash
# CSV -> xlsx 무손실 변환 (여러 개 한 번에)
python3 scripts/exping-csv-to-xlsx.py tmp/…/exping/*.csv \
    --theme-from 'tmp/20260722_CFI/TEST1/exping/FXA3000_RAIL_TEST1(1514_1534).xlsx'

# 보정된 pcap 에서 전 구간 로그 재구성
python3 scripts/exping-from-pcap.py tmp/sync/TEST1/pcap/wireshark/유선/cap_.pcapng \
    --out-dir tmp/sync/TEST1/exping --name 'FXE3000_TEST1(1457_1515)' \
    --theme-from 'tmp/20260722_CFI/TEST1/exping/FXA3000_RAIL_TEST1(1514_1534).xlsx'
```

`--theme-from` 은 표 스타일 색을 결정하는 테마를 기존 파일에서 가져온다. 생략하면
openpyxl 기본 테마라 표 색만 달라 보인다 (데이터는 같다).

> **반드시 유선 캡처를 넣어라.** 무선(모니터) 캡처에도 같은 ping 이 보이므로 도구는
> 아무 불평 없이 돌아가지만, 결과가 조용히 틀린다. 모니터는 프레임을 놓치고 그 누락이
> 전부 손실로 계산되기 때문이다. 같은 시험(2026-07-21 TEST1)을 두 캡처로 재구성한 실측:
>
> | 입력 | 행 | ＮＧ | 손실률 |
> |---|---:|---:|---:|
> | 유선 `FXE3000_1번테스트_1515_.pcapng` | 9,296 | 15 | **0.16%** |
> | 무선 `TEST1_.pcapng` | 11,224 | 1,757 | **15.65%** |
>
> 100배 차이다. 손실률이 예상보다 크면 입력 파일부터 확인한다.

## 형식

| 열 | 값 |
|---|---|
| 結果 | `ＯＫ` / `ＮＧ` (전각) |
| 日時 | `YYYY-MM-DD HH:MM:SS` — 초 단위, 소수점 없음 |
| 対象 | 대상 IP |
| ＩＰアドレス | 응답한 IP. ＮＧ 행은 공란 |
| ステータス | `Time:%6dms` / `Request timed out` / `Destination host unreachable` / `Unknown Error` |
| 備考 | 항상 공란 |

CSV 는 UTF-8 BOM + CRLF + 전 필드 인용이다. 머리글의 `ＩＰアドレス` 는 전각이라
`IP` 로 적으면 안 된다.

xlsx 는 시트가 2개다 — 사용자가 CSV 를 엑셀로 열고 시트를 복사한 흔적이다. 시트1은
`<이름> (2)` 로 엑셀 표(TableStyleMedium7)가 걸려 있고 B열이 `h:mm:ss;@`, 시트2는
`<이름>` 으로 서식 없이 B열이 `m/d/yy h:mm` 이다. 엑셀은 복사본 이름이 31자를 넘으면
**원래 이름 쪽**을 자른다 (`…TEST1(1514_1534)` → `…TEST1(1514_153 (2)`).

## 재구성 규칙

시간동기화된 기준쌍 `tmp/20260722_CFI/TEST1` (유선 pcap ↔ exping CSV, 10,433행)에서
역공학했다. 그 쌍에서 **echo request 1건 = 로그 1행**이 정확히 성립하고, 무응답 23건의
인덱스가 ＮＧ 23행의 인덱스와 완전히 일치한다.

| 열 | 규칙 |
|---|---|
| 結果 | 인정 시간 안에 응답 있으면 ＯＫ, 없으면 ＮＧ |
| 日時 | request 프레임 시각을 초 단위 절삭 |
| ステータス | `floor(왕복시간ms + RTT_OFFSET_MS)` 또는 타임아웃 문구 |

### 대상이 여러 개면 시각 순 그대로

한 로그에 `.21/.22/.23` 이 번갈아 나오는 캡처가 있다. 대상별로 나누지 않고 요청 시각
순 한 줄로 내면 된다 — 2026-07-23 TEST18 원본 1,000행과 대조했을 때 対象 순서가
1000/1000 일치했다.

### 정수 ms 보정값 0.276

와이어 왕복시간을 그대로 내림하면 안 맞는다. EXPING 이 쓰는 Windows `IcmpSendEcho` 의
측정구간이 와이어보다 조금 넓기 때문이다. 기준 표본 11,410건에 합동 적합한 값이
**+0.276 ms** 이고 정수 ms 일치율 95.0%, 빗나간 515건 중 514건이 ±1 ms 다.

완전 일치는 원리상 불가능하다 — 같은 와이어 왕복시간(0.7 ms)이 어떤 행에서는 0 ms,
어떤 행에서는 1 ms 로 기록된 사례가 실측에 있다. 실행마다 최적값이 0.28~0.44 ms 로
갈리므로 지연이 큰 캡처는 `--rtt-offset` 으로 조정한다.

### 응답 인정 상한 1초

2026-07-23 TEST14 에서 EXPING 이 ＮＧ 로 적은 31건의 실제 왕복시간이 1,011~2,088 ms
였다. 상한을 1초로 두면 그 캡처의 손실 판정이 99.94% → 100% 가 된다.

### 끝의 무응답 요청은 지운다

캡처가 응답보다 먼저 끊기면 마지막 요청이 ＮＧ 로 잘못 기록된다. 실측으로
2026-07-21 TEST7 캡처는 마지막 요청 **0.000초** 뒤에 끝났고, 그 행은 원본 EXPING
로그에 `ＯＫ 1 ms` 로 남아 있었다. 그래서 기본 동작은 꼬리의 무응답 요청을 지우는
것이다 (`--keep-trailing-lost` 로 끌 수 있다).

### 시계는 반영하지 않는다

원본 EXPING PC 의 시계 오차는 재현하지 않는다. 실측 범위가 −41.2초 ~ +0.08초로
날마다 달랐고, 한 실행 안에서도 20분에 0.03초씩 표류했다 — 도구 특성이 아니라
자유진동 시계 오차다. 출력 시각은 **입력 pcap 의 시각 그대로**이므로, NTP 로 보정한
pcap(`timesync-shift-pcap.py` 출력)을 넣으면 NTP 타임라인 위의 로그가 나온다.

## 스크립트

### `exping-csv-to-xlsx.py`

```bash
python3 scripts/exping-csv-to-xlsx.py <csv...> [옵션]
```

행을 그대로 옮긴다. ステータス 는 해석하지 않으므로 어떤 값이 와도 보존된다.
CSV 를 여러 개 나열할 수 있고, 하나가 실패해도 나머지는 계속 처리한 뒤 종료코드 1 을 낸다.

| 옵션 | 설명 |
|---|---|
| `--out-dir` | 출력 디렉터리. 생략하면 각 CSV 와 같은 자리에 만든다 |
| `--theme-from` | 표 스타일 테마를 가져올 기준 xlsx |
| `--overwrite` | 이미 xlsx 가 있어도 덮어쓴다 (기본은 건너뜀) |

```
$ python3 scripts/exping-csv-to-xlsx.py 'tmp/…/FXA5000_RAIL_TEST13(1125_1325).csv' \
      --out-dir tmp/sync3/TEST13/exping --theme-from "$REF"
 56,402행  tmp/sync3/TEST13/exping/FXA5000_RAIL_TEST13(1125_1325).xlsx
```

### `exping-from-pcap.py`

```bash
python3 scripts/exping-from-pcap.py <pcap> --out-dir D [옵션]
```

| 옵션 | 설명 |
|---|---|
| `--name` | 확장자 없는 출력 파일명. 생략 시 대상IP와 구간으로 자동 생성 |
| `--sender` | EXPING 실행 PC 의 IP. 기본은 요청을 가장 많이 보낸 호스트 |
| `--tz` | 日時 를 적을 타임존. 기본 `Asia/Seoul` |
| `--timeout` | 응답 인정 상한(초). 기본 1.0 |
| `--rtt-offset` | 정수 ms 변환 보정값. 기본 0.276 |
| `--theme-from` | 표 스타일 테마를 가져올 기준 xlsx |
| `--keep-trailing-lost` | 꼬리 무응답을 지우지 않는다 |
| `--allow-wireless` | 무선(802.11) 캡처도 허용. 손실률이 크게 부풀려지니 권하지 않는다 |
| `--csv-only` | xlsx 없이 csv 만 (openpyxl 불필요) |
| `--tshark` | tshark 경로 |

```
$ python3 scripts/exping-from-pcap.py 'tmp/sync/TEST7/pcap/wireshark/유선/FXA3000_TEST7(1629_1649)_.pcapng' \
      --out-dir tmp/sync/TEST7/exping --name 'FXA3000_TEST7(1628_1650)' --theme-from "$REF"
송신 192.168.0.31  대상 192.168.0.21(3,577), 192.168.0.22(3,577), 192.168.0.23(3,577)
꼬리 무응답 1행 삭제 — 응답이 캡처에 안 잡힌 것일 수 있어 ＮＧ 로 세지 않는다
10,731행  ＯＫ 10,699  ＮＧ 32  손실 0.298%
구간 2026-07-21 16:28:53 ~ 16:50:11 (Asia/Seoul)
wrote tmp/sync/TEST7/exping/FXA3000_TEST7(1628_1650).csv
wrote tmp/sync/TEST7/exping/FXA3000_TEST7(1628_1650).xlsx
```

## 레시피

### 캠페인 하나를 통째로 재구성

`timesync-batch.py` 출력 트리를 그대로 훑는다. 파일명은 원본 pcap 이름에서 따온다.

```bash
REF='tmp/20260722_CFI/TEST1/exping/FXA3000_RAIL_TEST1(1514_1534).xlsx'
for p in tmp/sync/*/pcap/wireshark/유선/*.pcapng; do
    test=$(echo "$p" | cut -d/ -f3)
    base=$(basename "$p" .pcapng); base=${base%_}
    python3 scripts/exping-from-pcap.py "$p" \
        --out-dir "tmp/sync/$test/exping" --name "$base" --theme-from "$REF"
done
```

### 원본 CSV 를 한꺼번에 xlsx 로

```bash
python3 scripts/exping-csv-to-xlsx.py tmp/2026072*_CFI/*/exping/*.csv --theme-from "$REF"
```

원본 캠페인 디렉터리에 쓰기 권한이 없으면 `--out-dir` 로 다른 트리에 낸다.

### 결과 확인

재구성이 맞았는지 보려면 남아 있는 원본 로그와 대조한다. 행 수가 크게 다르면
캡처 구멍이나 앞부분 잘림을 의심한다.

```bash
python3 - <<'PY'
import csv, io, collections
for p in ("원본.csv", "재구성.csv"):
    rows = list(csv.reader(io.StringIO(open(p, encoding="utf-8-sig", newline="").read())))[1:]
    res = collections.Counter(r[0] for r in rows)
    print(f"{p}: {len(rows):,}행 {dict(res)} {rows[0][1]} ~ {rows[-1][1]}")
PY
```

## 문제 해결

| 증상 | 원인과 대응 |
|---|---|
| `xlsx 출력에는 openpyxl 이 필요하다` | `pip install -r requirements-exping.txt`. 설치가 어려우면 `--csv-only` |
| `tshark 를 찾을 수 없다` | `--tshark /경로/tshark` 로 지정 |
| `PermissionError` | 캠페인 디렉터리가 root 소유인 경우가 있다. `--out-dir` 로 쓰기 가능한 곳에 낸다 |
| `ICMP echo request 가 없다` | 그 캡처에 ping 트래픽이 없다. DFK 모니터 캡처처럼 복호화가 안 된 파일일 수 있다 |
| `무선(802.11) 캡처다` | 유선 캡처를 넣어라. 정말 무선으로 봐야 하면 `--allow-wireless` |
| 재구성 행 수가 원본 로그보다 훨씬 적다 | 캡처 구멍 또는 앞부분 잘림. 「한계」 참조 |
| 대상이 섞여 나온다 | 정상이다. 여러 대상을 번갈아 ping 하면 EXPING 로그도 그 순서다 |
| ＮＧ 가 원본보다 많다 | `--timeout` 을 늘려본다. 지연이 큰 캡처에서는 늦게 온 응답을 놓쳤을 수 있다 |
| 정수 ms 가 원본과 1 씩 어긋난다 | 정상 범위다(95% 일치). 계통적으로 치우쳤으면 `--rtt-offset` 조정 |
| 표 색이 기존 파일과 다르다 | `--theme-from` 에 기준 xlsx 를 준다 |

## 한계

- **무선 캡처는 이제 막는다.** echo request 가 전부 802.11 프레임이면 오류로 거부한다
  (`--allow-wireless` 로 무시 가능). 유선+무선이 섞인 pcapng 는 같은 ping 이 두 번
  세어지므로 경고만 하고 진행한다. 파일 단위 encap 이 아니라 **프레임 단위**로 판정하는
  이유가 이것이다 — 인터페이스가 여럿인 pcapng 에서는 파일 단위 판정이 무의미하다.
- **앞부분 잘림.** 캡처가 ping 도중에 시작됐으면 그 앞은 복원할 수 없다. 캡처 첫
  프레임이 이미 echo request 면 그런 경우다. 그때 손실률은 캡처 구간 기준이지 시험
  전체 기준이 아니다.
- **캡처 구멍.** 유선 캡처가 중간에 프레임을 놓치면 그 구간이 통째로 빠진다. 실측으로
  2026-07-23 TEST9 유선 캡처는 172초를 놓쳤는데, 같은 구간에 EXPING 은 1,409행을
  정상 기록하고 있었다. 재구성 결과와 원본 로그의 행 수가 크게 다르면 이걸 의심한다.
- **빈 셀.** 사용자가 만든 xlsx 는 빈 칸에 빈 문자열을 넣지만 이 도구는 빈 셀을 쓴다
  (openpyxl 이 빈 문자열 셀을 온전히 쓰지 못한다). 화면과 pandas 는 같고
  `ISBLANK`/`COUNTA` 와 표 필터 드롭다운에서만 다르다.
- **`analyzer.core.ping_matching` 과 다르다.** 그쪽은 대시보드용 손실 통계라 802.11
  retry dedup 과 단방향 흐름 seq gap 추정이 들어간다. 이 모듈은 추론 없이 EXPING 의
  기록 규칙만 재현한다.
