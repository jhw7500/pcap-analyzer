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
        help="중단 후 재개용 — offset.json 이 있으면 측정을 건너뛰고 보정만 이어서 한다. "
        "보정본까지 모두 있으면 데이터셋 전체를 건너뛴다",
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


#: 자식 프로세스 상한(초). tshark/editcap 이 손상 캡처에서 멈추면 배치 전체가 매달린다.
#: 2시간 133MB 캡처 실측이 분 단위라 넉넉하게 잡는다.
CHILD_TIMEOUT = 3600

#: 명령 에코에서 값을 가려야 하는 플래그.
_SECRET_FLAGS = frozenset({"--psk"})


def mask_cmd(cmd: list[str]) -> str:
    """명령 에코용 문자열. PSK 같은 비밀값은 가린다.

    터미널·CI 로그·화면 공유에 평문으로 남는 것을 막는다. (프로세스 목록 노출은
    tshark CLI 구조상 못 막는다 — docs/TIMESYNC.md 참조.)
    """
    out: list[str] = []
    hide = False
    for part in cmd:
        if hide:
            out.append("***")
            hide = False
            continue
        out.append(part)
        hide = part in _SECRET_FLAGS
    return " ".join(out)


def shift_dst(pcap: str, dataset: Path | None, outdir: Path) -> Path:
    """2단계가 이 소스를 어디에 쓸지 계산한다.

    `timesync-shift-pcap.py` 의 계획 로직과 **같아야 한다** — 다르면 완료 판정이 틀린다.
    """
    src = Path(pcap)
    try:
        rel = src.resolve().relative_to(dataset.resolve()) if dataset else Path(src.name)
    except (ValueError, OSError):
        rel = Path(src.name)
    return outdir / rel


def shift_outputs_complete(usable: list[dict], dataset: str | None, outdir: Path) -> bool:
    """오프셋이 나온 소스의 보정본이 **모두** 있으면 True.

    존재만 본다. 강제종료로 잘린 파일은 못 거른다 — 다시 보정하는 쪽이
    측정보다 훨씬 싸므로 애매하면 다시 하는 편이 안전하다.
    """
    base = Path(dataset) if isinstance(dataset, str) else None
    return all(shift_dst(s["pcap"], base, outdir).is_file() for s in usable)


def run(cmd: list[str], log) -> int:
    """서브프로세스를 돌리며 출력을 그대로 흘려보낸다."""
    print(f"    $ {mask_cmd(cmd)}", flush=True)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CHILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"      [stderr] {CHILD_TIMEOUT}초 안에 끝나지 않아 중단했다", flush=True)
        return 124
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

        # --skip-existing 은 "중단 후 재개"용이다. offset.json 만 보고 데이터셋을 통째로
        # 건너뛰면, 측정 후 보정 전에 끊긴 배치는 보정본을 영영 못 만들면서 성공(skipped)으로
        # 보고된다. 측정만 재사용하고 보정 단계로 넘어간다.
        log: list[str] = []
        reused = bool(args.skip_existing and offset_json.is_file())
        if reused:
            print("    이미 측정됨 — 1단계 건너뜀 (기존 offset.json 재사용)")
            rc = 0
        else:
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

        # 1단계가 rc=0 이어도 결과 JSON 이 온전하다는 보장은 없다(디스크 가득참, 중단 등).
        try:
            doc = json.loads(offset_json.read_text(encoding="utf-8"))
            sources = doc["sources"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"    [!] 결과 JSON 을 읽을 수 없다: {exc}")
            summary.append({"dataset": ds.name, "status": f"bad-offset-json({type(exc).__name__})"})
            print()
            continue
        usable = [s for s in sources if s.get("log_shift_seconds") is not None]
        entry = {
            "dataset": ds.name,
            "status": "measured",
            "sources": len(usable),
            "shifts": {Path(s["pcap"]).name: s["log_shift_seconds"] for s in usable},
        }

        if args.measure_only or not usable:
            if reused:
                entry["status"] = "skipped"
        elif reused and shift_outputs_complete(usable, doc.get("dataset"), dst / "pcap"):
            print("    보정본도 모두 있음 — 건너뜀")
            entry["status"] = "skipped"
        else:
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
