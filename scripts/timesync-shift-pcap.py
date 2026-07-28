"""[2단계-pcap] 1단계에서 구한 오프셋만큼 pcap 타임스탬프를 이동해 새 파일로 쓴다.

1호기 로그는 NTP 로 규율되어 이미 맞아 있고, 어긋난 쪽은 캡처 장비 시계다.
따라서 정상적인 보정 방향은 **pcap 을 옮기는 것**이다. 로그를 옮기는
`timesync-apply.py` 는 특정 캡처의 타임라인에 억지로 맞춰야 할 때만 쓴다.

pcap 마다 자기 오프셋을 쓰므로 `--source` 로 하나를 고를 필요가 없다.
한 번 돌리면 모든 캡처가 동시에 NTP 서버 타임라인으로 모인다.

부호: 1단계의 `log_shift_seconds` 는 "캡처 시계 − NTP 서버 시계"다.
캡처가 24.3초 뒤처져 있으면 -24.3 이고, pcap 에는 +24.3 을 더해야 맞는다.
즉 pcap 보정량 = -log_shift_seconds 이며 이 값을 editcap -t 에 그대로 넘긴다.

원본은 절대 수정하지 않는다. 출력은 항상 별도 디렉터리다.

사용 예:
    python3 scripts/timesync-shift-pcap.py /tmp/TEST1_timesync_offset.json \\
        --out /tmp/TEST1_shifted/pcap

    python3 scripts/timesync-shift-pcap.py <결과JSON> --out <디렉터리> --dry-run
"""

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.core import timesync  # noqa: E402

#: 이 스크립트가 설정 파일에서 읽어들이는 키
USED_KEYS = ("source", "pcap_out", "editcap")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="timesync-shift-pcap.py",
        description="1단계 오프셋만큼 pcap 타임스탬프를 이동해 새 파일로 쓴다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("offset_json", help="1단계가 만든 결과 JSON")
    p.add_argument("-c", "--config", help="옵션 JSON 경로 (생략 시 자동 탐색)")
    p.add_argument("--no-config", action="store_true", help="설정 파일 자동 탐색을 끈다")
    p.add_argument("--out", dest="pcap_out", help="출력 디렉터리 (원본은 수정하지 않음)")
    p.add_argument(
        "--source",
        help="특정 pcap 만 처리 (이름 부분일치). 생략 시 오프셋이 산출된 전부를 처리한다.",
    )
    p.add_argument("--editcap", help="editcap 실행 경로")
    p.add_argument(
        "--force",
        action="store_true",
        help="1단계가 '이 오프셋을 그대로 쓰지 말라'고 경고해도 적용한다",
    )
    p.add_argument("--dry-run", action="store_true", help="쓰지 않고 계획만 보여준다")
    p.add_argument("--quiet", action="store_true")
    return p


def _fail(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def load_sources(path: Path, source: str | None) -> tuple[list[dict], Path | None]:
    """결과 JSON 에서 오프셋이 산출된 소스들을 읽는다."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        _fail(f"ERROR: 결과 JSON 을 읽을 수 없다 ({path}): {exc}")
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), list):
        _fail(f"ERROR: 1단계 결과 JSON 형식이 아니다 ({path}): 'sources' 배열이 없다.")

    picked, skipped = [], []
    for s in doc["sources"]:
        if not isinstance(s, dict):
            continue
        shift, pcap = s.get("log_shift_seconds"), s.get("pcap")
        if not isinstance(pcap, str):
            continue
        if not isinstance(shift, (int, float)):
            # 오프셋을 못 낸 pcap — 조용히 빼면 출력이 왜 줄었는지 알 수 없다.
            skipped.append(s)
            continue
        if source and source not in pcap:
            continue
        picked.append(s)
    if skipped:
        print(
            f"[!] 오프셋을 산출하지 못해 제외한 pcap {len(skipped)}개 "
            "(NTP 프레임이 없거나 복호화가 안 된 캡처):",
            file=sys.stderr,
        )
        for s in skipped[:10]:
            why = (s.get("warnings") or ["사유 미상"])[0]
            print(f"      {Path(s['pcap']).name} — {why}", file=sys.stderr)
    if not picked:
        hint = f" (--source {source!r} 와 일치하는 것 없음)" if source else ""
        _fail(f"ERROR: {path} 에 오프셋이 산출된 pcap 이 없다{hint}.")

    dataset = doc.get("dataset")
    return picked, Path(dataset) if isinstance(dataset, str) else None


def resolve_src(raw: str, dataset: Path | None) -> Path | None:
    """결과 JSON 에 적힌 pcap 경로를 실제 파일로 해석한다.

    1단계를 돌린 작업 디렉터리가 지금과 다를 수 있으므로 데이터셋 기준도 시도한다.
    """
    cand = Path(raw)
    if cand.is_file():
        return cand
    if dataset is not None:
        alt = dataset / cand.name
        if alt.is_file():
            return alt
        for found in dataset.rglob(cand.name):
            if found.is_file():
                return found
    return None


def main() -> int:
    args = build_parser().parse_args()
    offset_json = Path(args.offset_json)
    if not offset_json.is_file():
        print(f"ERROR: 결과 JSON 없음: {offset_json}", file=sys.stderr)
        return 2

    try:
        cfg, cfg_path = timesync.load_config(
            args.config or str(offset_json), search_from=offset_json, auto=not args.no_config
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    cli = {k: getattr(args, k, None) for k in USED_KEYS}
    opts = timesync.merge_options(cli, cfg)

    if not opts["pcap_out"]:
        print("ERROR: 출력 경로가 없다. --out 또는 설정의 pcap_out 을 지정하라.", file=sys.stderr)
        return 2
    outdir = Path(opts["pcap_out"])

    sources, dataset = load_sources(offset_json, opts["source"])

    warned = [w for s in sources for w in s.get("warnings", []) if w]
    for w in warned:
        print(f"[!] 1단계 경고: {w}", file=sys.stderr)
    if warned and not args.force:
        print(
            "ERROR: 1단계가 이 오프셋을 그대로 쓰지 말라고 경고했다. "
            "내용을 확인한 뒤에도 적용하려면 --force 를 붙여라.",
            file=sys.stderr,
        )
        return 2

    # (원본, 출력, 보정량) 계획을 먼저 전부 세운다 — 하나라도 문제가 있으면
    # 아무것도 쓰지 않는다.
    plan: list[tuple[Path, Path, float]] = []
    missing: list[str] = []
    for s in sources:
        src = resolve_src(s["pcap"], dataset)
        if src is None:
            missing.append(s["pcap"])
            continue
        if dataset is not None and timesync.paths_overlap(outdir, dataset):
            print(
                f"ERROR: --out({outdir}) 이 데이터셋({dataset}) 과 겹친다. "
                "원본 덮어쓰기를 막기 위해 무관한 경로를 지정하라.",
                file=sys.stderr,
            )
            return 2
        try:
            rel = src.resolve().relative_to(dataset.resolve()) if dataset else Path(src.name)
        except (ValueError, OSError):
            rel = Path(src.name)
        plan.append((src, outdir / rel, timesync.pcap_shift_seconds(s["log_shift_seconds"])))

    if missing:
        print(f"ERROR: pcap 파일을 찾을 수 없다 ({len(missing)}개):", file=sys.stderr)
        for m in missing[:10]:
            print(f"  {m}", file=sys.stderr)
        print("  1단계를 돌린 작업 디렉터리에서 실행하거나 경로를 확인하라.", file=sys.stderr)
        return 2

    if not args.quiet:
        if cfg_path:
            print(f"[*] 설정 파일: {cfg_path}")
        print(f"[*] 기준     : NTP 서버 시각 (1단계 결과 {offset_json})")
        print(f"[*] 대상     : pcap {len(plan)}개")
        print(f"[*] 출력     : {outdir}{'  [dry-run]' if args.dry_run else ''}")
        print()

    done = 0
    for src, dst, delta in plan:
        if not args.quiet:
            print(f"    {src.name:<40} {delta:+14.6f} s", flush=True)
        try:
            timesync.shift_pcap_file(
                src, dst, delta, editcap_path=opts["editcap"], dry_run=args.dry_run
            )
        except (RuntimeError, OSError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        done += 1

    if not args.quiet:
        print()
        print(f"[*] 완료: {done}/{len(plan)}개")
        if args.dry_run:
            print("[*] dry-run 이므로 파일을 쓰지 않았다.")
        else:
            print("[*] 보정된 pcap 은 1호기 로그와 같은 NTP 타임라인 위에 있다.")
    return 0 if done else 1


if __name__ == "__main__":
    sys.exit(main())
