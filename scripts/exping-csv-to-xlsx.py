"""EXPING 이 뽑은 CSV 를 기준 파일과 같은 서식의 xlsx 로 무손실 변환한다.

pcap 재구성이 아니다 — 원본 CSV 의 행을 그대로 옮긴다. ステータス 도 해석하지 않고
문자열 그대로 복사하므로 'Time: N ms' / 'Request timed out' 외에
'Destination host unreachable', 'Unknown Error' 같은 값도 보존된다.

원본 EXPING 로그가 있으면 `exping-from-pcap.py` 대신 항상 이쪽을 써라. 재구성은
왕복시간 정수 ms 를 95% 만 맞히지만 이 변환은 100% 다.

서식 기준은 사용자가 엑셀로 만든 xlsx 다 — 시트 2개(표 시트 + 원본 시트), 엑셀 표
TableStyleMedium7, 열 너비, 시각 서식, 맑은 고딕 11. `--theme-from` 으로 기준 xlsx 를
주면 표 색까지 맞는다.

사용 예:
    python3 scripts/exping-csv-to-xlsx.py tmp/.../exping/FOO\\(1539_1559\\).csv

    python3 scripts/exping-csv-to-xlsx.py tmp/.../*.csv --out-dir /tmp/out \\
        --theme-from tmp/20260722_CFI/TEST1/exping/FXA3000_RAIL_TEST1\\(1514_1534\\).xlsx
"""

import argparse
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.core import exping  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("csv", nargs="+", help="EXPING CSV (여러 개 가능)")
    p.add_argument("--out-dir", help="출력 디렉터리. 생략 시 CSV 와 같은 자리")
    p.add_argument("--theme-from", help="표 스타일 테마를 가져올 기준 xlsx")
    p.add_argument("--overwrite", action="store_true", help="이미 있는 xlsx 도 덮어쓴다")
    return p


def _fail(msg: str) -> NoReturn:
    print(f"[!] {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    args = build_parser().parse_args()

    failed = 0
    for raw in args.csv:
        src = Path(raw)
        if not src.exists():
            print(f"[!] 없는 파일: {src}", file=sys.stderr)
            failed += 1
            continue
        out_dir = Path(args.out_dir) if args.out_dir else src.parent
        out = out_dir / f"{src.stem}.xlsx"
        if out.exists() and not args.overwrite:
            print(f"건너뜀 (이미 있음): {out}")
            continue

        try:
            rows = exping.read_csv(src)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            failed += 1
            continue
        if not rows:
            print(f"[!] 데이터 행이 없다: {src}", file=sys.stderr)
            failed += 1
            continue

        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            exping.write_xlsx(out, rows, src.stem, args.theme_from)
        except RuntimeError as exc:
            _fail(str(exc))
        except OSError as exc:
            print(f"[!] 쓰기 실패: {exc}", file=sys.stderr)
            failed += 1
            continue
        print(f"{len(rows):7,d}행  {out}")

    if failed:
        print(f"[!] {failed}개 실패", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
