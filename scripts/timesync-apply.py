"""[2단계] 1단계에서 구한 오프셋을 로그 파일 타임스탬프에 일괄 적용해 새로 쓴다.

원본은 건드리지 않고 항상 새 디렉터리에 결과를 만든다.

옵션은 CLI 로 주거나 JSON 설정 파일에 담을 수 있다.
우선순위: CLI 인자 > 설정 파일 > 내장 기본값.
설정 파일은 --config 로 지정하거나, <logdir>/timesync.json →
<logdir>/../timesync.json → ./timesync.json 순으로 자동 탐색된다.
--config 에 1단계 결과 JSON 을 주면 옵션과 오프셋을 한 파일에서 모두 읽는다
(--offset-file 을 따로 줄 필요가 없다).

지원 타임스탬프 포맷 (모두 줄 시작 앵커):
    2026-07-21 14:57:01.205 ...        cpu/kern/logger/summary/sys/wpa.log, DFK AP logfile
    [2026-07-21 14:57:02] ...          ap/freq/stat.log
    ===== 2026-07-21 14:57:04 =====    snap.log
앵커가 없는 본문 속 날짜(예: "NTP: Setting clock (2015-01-01 00:00:07)")는
건드리지 않는다. 타임스탬프가 없는 줄은 그대로 복사된다.

사용 예:
    python3 scripts/timesync-apply.py tmp/20260721_CFI/TEST1/1호기 \\
        --config tmp/20260721_CFI/TEST1/timesync_offset.json \\
        --source FXE3000 --out /출력/경로

    python3 scripts/timesync-apply.py <로그디렉터리> --offset -24.3173 --out <출력디렉터리>
"""

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.core import timesync  # noqa: E402

#: 이 스크립트가 설정 파일에서 읽어들이는 키
USED_KEYS = ("offset", "source", "apply_out", "glob", "pattern")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="timesync-apply.py",
        description="로그 타임스탬프에 오프셋을 일괄 적용해 새 파일로 쓴다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("logdir", help="보정할 로그 디렉터리 또는 파일")
    p.add_argument(
        "-c",
        "--config",
        help=f"옵션 JSON 경로. 생략 시 {timesync.CONFIG_FILENAME} 를 자동 탐색한다. "
        "1단계 결과 JSON 을 주면 오프셋까지 이 파일에서 읽는다.",
    )
    p.add_argument("--no-config", action="store_true", help="설정 파일 자동 탐색을 끈다")
    p.add_argument("--offset", type=float, help="적용할 오프셋(초). 로그 시각에 더해진다.")
    p.add_argument("--offset-file", dest="offset_file", help="1단계가 만든 결과 JSON 경로")
    p.add_argument(
        "--source",
        help="결과 JSON 안에서 쓸 pcap 이름(부분일치 가능). "
        "생략 시 오프셋이 산출된 소스가 하나뿐이면 그것을 쓴다.",
    )
    p.add_argument("--out", dest="apply_out", help="출력 디렉터리 (원본은 수정하지 않음)")
    p.add_argument(
        "--glob",
        action="append",
        metavar="PATTERN",
        help=f"대상 파일 glob. 반복 지정 가능. 기본 {list(timesync.DEFAULT_LOG_GLOBS)}",
    )
    p.add_argument(
        "--pattern",
        action="append",
        metavar="REGEX",
        help="추가 타임스탬프 정규식. 반드시 (?P<ts>...) 그룹과 ^ 앵커를 포함해야 한다.",
    )
    p.add_argument(
        "--print-config",
        action="store_true",
        help="병합된 최종 옵션을 JSON 으로 출력하고 종료한다",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="1단계가 '이 오프셋을 그대로 쓰지 말라'고 경고해도 적용한다",
    )
    p.add_argument("--dry-run", action="store_true", help="쓰지 않고 변경 건수만 보여준다")
    p.add_argument("--quiet", action="store_true")
    return p


def _fail(msg: str) -> NoReturn:
    """사용법 오류로 종료한다. 종료코드는 다른 인자 오류와 같은 2 로 맞춘다."""
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def _is_offset_document(path: Path) -> bool:
    """1단계 결과 JSON 인지 (sources 배열을 가졌는지) 판별한다."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    return isinstance(doc, dict) and isinstance(doc.get("sources"), list)


def offset_from_document(path: Path, source: str | None) -> tuple[float, str, list[str]]:
    """1단계 결과 JSON 에서 적용할 오프셋을 고른다.

    Returns:
        (오프셋, 출처 설명, 1단계가 남긴 경고 목록)
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        _fail(f"ERROR: 결과 JSON 을 읽을 수 없다 ({path}): {exc}")
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), list):
        _fail(f"ERROR: 1단계 결과 JSON 형식이 아니다 ({path}): 'sources' 배열이 없다.")
    sources = []
    for s in doc["sources"]:
        if not isinstance(s, dict):
            continue
        shift, pcap = s.get("log_shift_seconds"), s.get("pcap")
        if not isinstance(shift, (int, float)) or not isinstance(pcap, str):
            continue
        sources.append(s)
    if not sources:
        _fail(f"ERROR: {path} 에 오프셋이 산출된 소스가 없다. 1단계를 다시 확인하라.")

    if source:
        hit = [s for s in sources if source in s["pcap"]]
        if not hit:
            names = "\n  ".join(s["pcap"] for s in sources)
            _fail(f"ERROR: source {source!r} 와 일치하는 소스 없음. 후보:\n  {names}")
        if len(hit) > 1:
            names = "\n  ".join(s["pcap"] for s in hit)
            _fail(f"ERROR: source {source!r} 가 여러 소스와 일치한다:\n  {names}")
        chosen = hit[0]
    elif len(sources) == 1:
        chosen = sources[0]
    else:
        names = "\n  ".join(f"{s['pcap']}  ({s['log_shift_seconds']:+.6f}s)" for s in sources)
        _fail(f"ERROR: 소스가 여러 개다. --source 로 지정하라:\n  {names}")

    # 로그 보정은 offset 자체의 문제(warnings)와 장치 시계 문제(log_warnings)를 모두 본다.
    warnings = [str(w) for w in chosen.get("warnings", []) if w]
    warnings += [str(w) for w in chosen.get("log_warnings", []) if w]
    if chosen.get("method") == "ntp-only":
        # 로그를 옮기려면 장치 시계가 NTP 규율 상태여야 하는데, 대응 sys.log 가
        # 없어 그 검증을 못 했다. pcap 보정과 달리 여기서는 막아야 한다.
        warnings.append(
            "이 오프셋은 대응 sys.log 없이 NTP 프레임만으로 산출됐다 — "
            "장치 시계 검증이 불가능하므로 로그 보정 기준으로 삼으면 안 된다."
        )
    return float(chosen["log_shift_seconds"]), chosen["pcap"], warnings


def main() -> int:
    args = build_parser().parse_args()
    logdir = Path(args.logdir)

    try:
        cfg, cfg_path = timesync.load_config(
            args.config, search_from=logdir, auto=not args.no_config
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    cli = {k: getattr(args, k, None) for k in USED_KEYS}
    opts = timesync.merge_options(cli, cfg)

    if args.print_config:
        json.dump({"timesync": opts}, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0

    if not logdir.exists():
        print(f"ERROR: 경로 없음: {logdir}", file=sys.stderr)
        return 2

    # 오프셋 결정: --offset(또는 설정의 offset) > --offset-file > 1단계 결과인 --config
    stage1_warnings: list[str] = []
    if opts["offset"] is not None:
        offset = opts["offset"]
        # 설정 파일이 조용히 주입한 값을 "직접 지정"이라 표기하면 거짓말이 된다.
        origin = (
            "--offset 직접 지정"
            if args.offset is not None
            else f"설정 파일의 offset 키 ({cfg_path})"
        )
    else:
        doc_path = None
        if args.offset_file:
            doc_path = Path(args.offset_file)
            if not doc_path.is_file():
                print(f"ERROR: 결과 JSON 없음: {doc_path}", file=sys.stderr)
                return 2
        elif cfg_path is not None and _is_offset_document(cfg_path):
            doc_path = cfg_path
        if doc_path is None:
            print(
                "ERROR: 오프셋을 알 수 없다. --offset 으로 직접 주거나, "
                "--offset-file/--config 로 1단계 결과 JSON 을 지정하라.",
                file=sys.stderr,
            )
            return 2
        offset, origin, stage1_warnings = offset_from_document(doc_path, opts["source"])

    for w in stage1_warnings:
        print(f"[!] 1단계 경고: {w}", file=sys.stderr)
    if stage1_warnings and not args.force:
        print(
            "ERROR: 1단계가 이 오프셋을 그대로 쓰지 말라고 경고했다. "
            "내용을 확인한 뒤에도 적용하려면 --force 를 붙여라.",
            file=sys.stderr,
        )
        return 2

    if not opts["apply_out"]:
        print("ERROR: 출력 경로가 없다. --out 또는 설정의 apply_out 을 지정하라.", file=sys.stderr)
        return 2
    outdir = Path(opts["apply_out"])

    base = logdir if logdir.is_dir() else logdir.parent
    if timesync.paths_overlap(outdir, base):
        print(
            f"ERROR: --out({outdir}) 과 입력 트리({base}) 가 겹친다. "
            "안이면 이중 보정, 위면 형제 원본 덮어쓰기가 발생한다 — 서로 무관한 경로를 지정하라.",
            file=sys.stderr,
        )
        return 2

    globs = tuple(opts["glob"])
    files = timesync.find_log_files(logdir, globs)
    if not files:
        print(f"ERROR: 대상 파일 없음 ({logdir}, glob={list(globs)})", file=sys.stderr)
        return 1

    patterns = list(timesync.DEFAULT_LOG_PATTERNS) + list(opts["pattern"])
    try:
        compiled = timesync.compile_patterns(patterns)
    except Exception as exc:
        print(f"ERROR: 타임스탬프 정규식 컴파일 실패: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        if cfg_path:
            print(f"[*] 설정 파일: {cfg_path}")
        print(f"[*] 오프셋 : {offset:+.6f} s   (출처: {origin})")
        print(f"[*] 대상   : {len(files)}개 파일  ({logdir})")
        print(f"[*] 출력   : {outdir}{'  [dry-run]' if args.dry_run else ''}")
        print()

    # 쓰기 전 전수 검사 — 출력 경로가 하나라도 --out 밖으로 나가면 아무것도
    # 쓰지 않고 중단한다. 부분 기록을 남기면 원본 일부만 파괴된 상태가 된다.
    pairs, escaped = timesync.plan_output_paths(files, base, outdir)
    if escaped:
        print(
            f"ERROR: 출력 경로가 --out({outdir}) 밖으로 나가는 대상이 "
            f"{len(escaped)}개 있다. 원본을 덮어쓸 수 있으므로 중단한다:",
            file=sys.stderr,
        )
        for p in escaped[:10]:
            print(f"  {p}", file=sys.stderr)
        print("  --glob 에 '..' 가 들어있지 않은지 확인하라.", file=sys.stderr)
        return 2

    total_lines = total_changed = 0
    untouched = []
    for src, dst in pairs:
        rel = dst.relative_to(outdir)
        lines, changed = timesync.shift_log_file(
            src, dst, offset, patterns=compiled, dry_run=args.dry_run
        )
        total_lines += lines
        total_changed += changed
        if changed == 0:
            untouched.append(rel)
        if not args.quiet:
            print(f"    {str(rel):<28} {changed:>6}/{lines:<6} 줄 이동")

    if not args.quiet:
        print()
        print(f"[*] 합계: {total_changed:,}/{total_lines:,} 줄 이동")
        if untouched:
            print(
                f"[!] 타임스탬프를 찾지 못한 파일 {len(untouched)}개: "
                f"{', '.join(str(u) for u in untouched[:5])}"
                f"{' ...' if len(untouched) > 5 else ''}"
            )
            print("    포맷이 다르면 --pattern 으로 정규식을 추가하라.")
        if args.dry_run:
            print("[*] dry-run 이므로 파일을 쓰지 않았다.")
    return 0 if total_changed else 1


if __name__ == "__main__":
    sys.exit(main())
