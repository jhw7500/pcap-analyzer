"""pcap 의 ICMP echo 교환에서 EXPING 형식 로그(csv+xlsx)를 재구성한다.

EXPING 로그가 없거나, 있어도 쓸 수 없을 때를 위한 도구다. 실제로 2026-07-21 캠페인은
로그가 마지막 1,000행(약 2분)만 남아 있었고 그나마 시계가 41초 어긋나 있었다.
`timesync-shift-pcap.py` 로 NTP 타임라인에 맞춘 pcap 에 이 도구를 돌리면 전 구간 로그를
맞는 시각으로 되살릴 수 있다.

**원본 EXPING 로그가 온전하다면 이 도구를 쓰지 마라.** `exping-csv-to-xlsx.py` 로
그대로 옮기는 쪽이 항상 낫다. 재구성은 왕복시간 정수 ms 를 95% 만 맞히고,
'Destination host unreachable' 같은 값은 만들어낼 수 없다.

日時 에는 원본 EXPING PC 의 시계 오차를 반영하지 않는다. 그 오차는 자유진동 시계
오차라서(실측 범위 −41.2초 ~ +0.08초) 반영하면 pcap 타임라인이 깨진다. 출력 시각은
입력 pcap 의 시각 그대로다 — 보정된 pcap 을 넣으면 보정된 시각이 나온다.

사용 예:
    python3 scripts/exping-from-pcap.py tmp/sync/TEST1/pcap/wireshark/유선/cap_.pcapng \\
        --out-dir tmp/sync/TEST1/exping --name "FXE3000_TEST1(1457_1515)"

    # 표 색까지 기존 파일과 맞추려면 기준 xlsx 를 준다
    python3 scripts/exping-from-pcap.py <pcap> --out-dir <디렉터리> \\
        --theme-from tmp/20260722_CFI/TEST1/exping/FXA3000_RAIL_TEST1\\(1514_1534\\).xlsx
"""

import argparse
import collections
import datetime as dt
import os
import sys
import time
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.core import exping  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("pcap", help="읽을 pcap/pcapng")
    p.add_argument("--out-dir", required=True, help="출력 디렉터리")
    p.add_argument("--name", help="확장자 없는 출력 파일명. 생략 시 대상IP와 구간으로 자동 생성")
    p.add_argument("--sender", help="EXPING 을 실행한 호스트 IP (기본: 요청이 가장 많은 호스트)")
    p.add_argument("--tz", default="Asia/Seoul", help="日時 를 적을 타임존 (기본 Asia/Seoul)")
    p.add_argument(
        "--timeout",
        type=float,
        default=exping.DEFAULT_REPLY_TIMEOUT,
        help=f"응답 인정 상한(초). 기본 {exping.DEFAULT_REPLY_TIMEOUT}",
    )
    p.add_argument(
        "--rtt-offset",
        type=float,
        default=exping.RTT_OFFSET_MS,
        help=f"정수 ms 변환 보정값. 기본 {exping.RTT_OFFSET_MS}",
    )
    p.add_argument("--theme-from", help="표 스타일 테마를 가져올 기준 xlsx")
    p.add_argument("--keep-trailing-lost", action="store_true",
                   help="끝의 무응답 요청을 지우지 않는다 (기본은 지움 — ＮＧ 오탐 방지)")
    p.add_argument("--csv-only", action="store_true", help="xlsx 없이 csv 만 쓴다")
    p.add_argument("--tshark", default="tshark", help="tshark 실행 경로")
    return p


def _fail(msg: str) -> NoReturn:
    print(f"[!] {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    args = build_parser().parse_args()

    if not Path(args.pcap).exists():
        _fail(f"pcap 이 없다: {args.pcap}")
    os.environ["TZ"] = args.tz
    time.tzset()

    try:
        exchanges, sender = exping.extract_exchanges(
            args.pcap, tshark=args.tshark, sender=args.sender, timeout=args.timeout
        )
    except FileNotFoundError:
        _fail(f"tshark 를 찾을 수 없다: {args.tshark}")
    except ValueError as exc:
        _fail(str(exc))
    if not exchanges:
        _fail(f"{sender} 가 보낸 echo request 가 없다")

    dropped = 0
    if not args.keep_trailing_lost:
        exchanges, dropped = exping.drop_trailing_unanswered(exchanges)
        if not exchanges:
            _fail("응답 있는 요청이 하나도 없다")

    rows = exping.exchanges_to_rows(exchanges, args.rtt_offset)
    first = dt.datetime.fromtimestamp(exchanges[0].time)
    last = dt.datetime.fromtimestamp(exchanges[-1].time)
    base = args.name or f"exping_{sender}({first:%H%M}_{last:%H%M})"

    out_dir = Path(args.out_dir)
    csv_path = out_dir / f"{base}.csv"
    xlsx_path = out_dir / f"{base}.xlsx"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        exping.write_csv(csv_path, rows)
        written = [csv_path]
        if not args.csv_only:
            exping.write_xlsx(xlsx_path, rows, base, args.theme_from)
            written.append(xlsx_path)
    except RuntimeError as exc:  # openpyxl 없음
        _fail(str(exc))
    except OSError as exc:  # 권한 없음, 디스크 가득 참 등
        _fail(f"쓰기 실패: {exc}")

    ng = sum(1 for e in exchanges if not e.answered)
    targets = collections.Counter(e.target for e in exchanges)
    print(f"송신 {sender}  대상 " + ", ".join(f"{k}({v:,})" for k, v in sorted(targets.items())))
    if dropped:
        print(f"꼬리 무응답 {dropped}행 삭제 — 응답이 캡처에 안 잡힌 것일 수 있어 ＮＧ 로 세지 않는다")
    print(f"{len(rows):,}행  ＯＫ {len(rows) - ng:,}  ＮＧ {ng}  손실 {ng / len(rows) * 100:.3f}%")
    print(f"구간 {first:%Y-%m-%d %H:%M:%S} ~ {last:%H:%M:%S} ({args.tz})")
    for p in written:
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
