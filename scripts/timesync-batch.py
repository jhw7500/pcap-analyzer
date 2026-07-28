"""[일괄] 여러 테스트셋에 대해 1단계(측정) → 2단계(pcap 보정)를 한 번에 돌린다.

루트 디렉터리 아래에서 sys.log 를 가진 데이터셋을 모두 찾아 각각 처리한다.
결과는 데이터셋별로 <out>/<이름>/ 아래에 모인다:

    <out>/<이름>/offset.json     1단계 측정 결과
    <out>/<이름>/pcap/...        NTP 타임라인으로 보정된 pcap

원본 디렉터리에는 아무것도 쓰지 않는다.

사용 예:
    python3 scripts/timesync-batch.py tmp/20260721_CFI --out tmp/sync \\
        --ssid CANTOPS_TEST --psk <passphrase>

    python3 scripts/timesync-batch.py tmp/20260722_CFI --out tmp/sync --skip-existing
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.core import timesync  # noqa: E402

HERE = Path(__file__).resolve().parent
OFFSET_CLI = HERE / "timesync-offset.py"
SHIFT_CLI = HERE / "timesync-shift-pcap.py"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="timesync-batch.py",
        description="여러 테스트셋의 시각 오프셋을 측정하고 pcap 을 일괄 보정한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("root", help="테스트셋들이 들어있는 루트 (예: tmp/20260721_CFI)")
    p.add_argument("--out", required=True, help="출력 루트 (예: tmp/sync)")
    p.add_argument("--ssid", help="WPA 복호화용 SSID")
    p.add_argument("--psk", help="WPA 복호화용 passphrase")
    p.add_argument("--tz", help="로그 타임존 (IANA 이름 또는 +09:00)")
    p.add_argument("--tolerance", type=float, help="sys.log ↔ ntp.org 허용오차(초)")
    p.add_argument("--tshark", help="tshark 실행 경로")
    p.add_argument("--editcap", help="editcap 실행 경로")
    p.add_argument(
        "--skip-existing",
        action="store_true",
        help="이미 offset.json 이 있는 데이터셋은 건너뛴다 (중단 후 재개용)",
    )
    p.add_argument(
        "--measure-only",
        action="store_true",
        help="1단계 측정만 하고 pcap 보정은 하지 않는다",
    )
    p.add_argument("--dry-run", action="store_true", help="처리 대상만 나열하고 끝낸다")
    return p


def find_datasets(root: Path) -> list[Path]:
    """sys.log 를 가진 데이터셋 디렉터리를 찾는다.

    <root>/<name>/**/sys.log 구조를 가정하고, 데이터셋은 <root>/<name> 이다.
    """
    found: dict[Path, None] = {}
    for syslog in sorted(root.rglob("sys.log")):
        try:
            rel = syslog.relative_to(root)
        except ValueError:
            continue
        if not rel.parts:
            continue
        found.setdefault(root / rel.parts[0], None)
    return list(found)


def run(cmd: list[str], log) -> int:
    """서브프로세스를 돌리며 출력을 그대로 흘려보낸다."""
    print(f"    $ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    for line in (proc.stdout or "").splitlines():
        print(f"      {line}", flush=True)
    for line in (proc.stderr or "").splitlines():
        print(f"      [stderr] {line}", flush=True)
    log.extend((proc.stdout or "").splitlines())
    return proc.returncode


def main() -> int:
    args = build_parser().parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"ERROR: 디렉터리 없음: {root}", file=sys.stderr)
        return 2

    outroot = Path(args.out)
    if timesync.paths_overlap(outroot, root):
        print(
            f"ERROR: --out({outroot}) 이 입력({root}) 과 겹친다. 무관한 경로를 지정하라.",
            file=sys.stderr,
        )
        return 2

    datasets = find_datasets(root)
    if not datasets:
        print(f"ERROR: sys.log 를 가진 데이터셋이 없다: {root}", file=sys.stderr)
        return 2

    print(f"[*] 루트   : {root}")
    print(f"[*] 출력   : {outroot}")
    print(f"[*] 데이터셋: {len(datasets)}개 — {', '.join(d.name for d in datasets)}")
    print()
    if args.dry_run:
        for d in datasets:
            print(f"  {d}  ->  {outroot / d.name}")
        return 0

    passthru: list[str] = []
    for flag, value in (
        ("--ssid", args.ssid),
        ("--psk", args.psk),
        ("--tz", args.tz),
        ("--tshark", args.tshark),
    ):
        if value:
            passthru += [flag, str(value)]
    if args.tolerance is not None:
        passthru += ["--tolerance", str(args.tolerance)]

    summary: list[dict] = []
    t0 = time.monotonic()
    for i, ds in enumerate(datasets, 1):
        dst = outroot / ds.name
        offset_json = dst / "offset.json"
        elapsed = time.monotonic() - t0
        print(f"=== [{i}/{len(datasets)}] {ds.name}  (경과 {elapsed / 60:.1f}분) ===", flush=True)

        if args.skip_existing and offset_json.is_file():
            print("    이미 측정됨 — 건너뜀")
            summary.append({"dataset": ds.name, "status": "skipped"})
            print()
            continue

        log: list[str] = []
        rc = run(
            [sys.executable, str(OFFSET_CLI), str(ds), "--no-config", "-o", str(offset_json)]
            + passthru,
            log,
        )
        if rc != 0 or not offset_json.is_file():
            print(f"    [!] 1단계 실패 (rc={rc})")
            summary.append({"dataset": ds.name, "status": f"measure-failed(rc={rc})"})
            print()
            continue

        doc = json.loads(offset_json.read_text(encoding="utf-8"))
        usable = [s for s in doc["sources"] if s.get("log_shift_seconds") is not None]
        entry = {
            "dataset": ds.name,
            "status": "measured",
            "sources": len(usable),
            "shifts": {Path(s["pcap"]).name: s["log_shift_seconds"] for s in usable},
        }

        if not args.measure_only and usable:
            rc = run(
                [sys.executable, str(SHIFT_CLI), str(offset_json), "--out", str(dst / "pcap")]
                + (["--editcap", args.editcap] if args.editcap else []),
                log,
            )
            entry["status"] = "shifted" if rc == 0 else f"shift-failed(rc={rc})"
        summary.append(entry)
        print()

    (outroot / "batch_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print("=" * 72)
    print(f"[*] 완료 — 총 {(time.monotonic() - t0) / 60:.1f}분")
    print(f"{'데이터셋':<10} {'상태':<22} {'소스':>4}  오프셋(초)")
    print("-" * 72)
    for e in summary:
        shifts = e.get("shifts") or {}
        rng = ""
        if shifts:
            vals = sorted(shifts.values())
            rng = f"{vals[0]:+.3f} ~ {vals[-1]:+.3f}" if len(vals) > 1 else f"{vals[0]:+.3f}"
        print(f"{e['dataset']:<10} {e['status']:<22} {e.get('sources', 0):>4}  {rng}")
    print()
    print(f"[*] 요약 저장: {outroot / 'batch_summary.json'}")
    ok = sum(1 for e in summary if e["status"] in ("shifted", "measured", "skipped"))
    return 0 if ok == len(summary) else 1


if __name__ == "__main__":
    sys.exit(main())
