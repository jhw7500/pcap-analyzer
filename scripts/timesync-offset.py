"""[1단계] sys.log 동기화 이벤트 ↔ pcap NTP 프레임 대조로 시각 오프셋을 산출한다.

sys.log 의 "Contacted time server" 시각과, pcap NTP 응답 프레임의
`ntp.org`(origin timestamp)를 짝지어 동일 이벤트를 찾은 뒤,
`frame.time_epoch - ntp.xmt` 로 캡처 장비 시계의 오차를 구한다.

옵션은 CLI 로 주거나 JSON 설정 파일에 담을 수 있다.
우선순위: CLI 인자 > 설정 파일 > 내장 기본값.
설정 파일은 --config 로 지정하거나, <dataset>/timesync.json →
<dataset>/../timesync.json → ./timesync.json 순으로 자동 탐색된다.

결과 JSON 에는 이번에 쓰인 옵션이 "options" 로 함께 저장되므로,
그 파일을 그대로 --config 로 되먹여 같은 설정을 재사용할 수 있다.

사용 예:
    python3 scripts/timesync-offset.py tmp/20260721_CFI/TEST1
    python3 scripts/timesync-offset.py tmp/20260722_CFI/TEST1 --config timesync.json
    python3 scripts/timesync-offset.py tmp/20260723_CFI/TEST5 \\
        --config tmp/20260722_CFI/TEST1/timesync_offset.json
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.core import timesync  # noqa: E402

#: 소스별 오프셋이 이보다 더 벌어져야 "직접 고르라" 경고를 낸다(초).
_SPREAD_WARN = 0.1

#: 이 스크립트가 설정 파일에서 읽어들이는 키
USED_KEYS = (
    "syslog",
    "pcap",
    "ssid",
    "psk",
    "tshark",
    "tz",
    "tolerance",
    "sync_pattern",
    "offset_out",
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="timesync-offset.py",
        description="sys.log 와 pcap NTP 프레임을 대조해 캡처 시각 오프셋을 산출한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("dataset", help="테스트셋 디렉터리 (예: tmp/20260721_CFI/TEST1)")
    p.add_argument(
        "-c",
        "--config",
        help=f"옵션 JSON 경로. 생략 시 {timesync.CONFIG_FILENAME} 를 자동 탐색한다. "
        "1단계 결과 JSON 도 그대로 받아들인다.",
    )
    p.add_argument(
        "--no-config",
        action="store_true",
        help="설정 파일 자동 탐색을 끈다 (CLI 인자와 내장 기본값만 사용)",
    )
    p.add_argument("--syslog", help="sys.log 경로. 생략 시 dataset 하위에서 자동 탐색한다.")
    p.add_argument(
        "--pcap",
        action="append",
        metavar="PATH",
        help="분석할 pcap. 반복 지정 가능. 생략 시 dataset 하위 전체를 자동 탐색한다.",
    )
    p.add_argument("--ssid", help="WPA 복호화용 SSID (암호화된 802.11 캡처에 필요)")
    p.add_argument("--psk", help="WPA 복호화용 passphrase")
    p.add_argument(
        "-o",
        "--out",
        dest="offset_out",
        help="결과 JSON 경로. 생략 시 <dataset>/timesync_offset.json",
    )
    p.add_argument(
        "--tolerance",
        type=float,
        help="sys.log 시각과 ntp.org 의 허용 오차(초). 기본 1.0 "
        "(왕복시간+로깅지연 실측 중앙값 0.43s)",
    )
    p.add_argument(
        "--sync-pattern",
        dest="sync_pattern",
        help=f"동기화 이벤트 정규식. 기본 {timesync.DEFAULT_SYNC_PATTERN!r}",
    )
    p.add_argument("--tshark", help="tshark 실행 경로")
    p.add_argument(
        "--tz",
        help="로그 타임스탬프의 타임존. IANA 이름(예 Asia/Seoul) 또는 고정 오프셋(예 +09:00). "
        "생략 시 이 머신의 로컬 타임존으로 해석한다 — 캡처 장비와 TZ 가 다르면 반드시 지정하라.",
    )
    p.add_argument(
        "--print-config",
        action="store_true",
        help="병합된 최종 옵션을 JSON 으로 출력하고 종료한다 (설정 파일 템플릿 생성용)",
    )
    p.add_argument("--quiet", action="store_true", help="사람이 읽는 요약 출력을 생략한다")
    return p


def _resolve_tshark(path: str) -> tuple[str, str | None]:
    """tshark 를 찾지 못하면 프로젝트 config 의 탐지 로직으로 폴백한다.

    Returns:
        (사용할 경로, 경고 메시지 또는 None)

    지정한 경로를 조용히 다른 바이너리로 바꿔치기하면 버전 차이로 결과가
    달라져도 알 수 없으므로, 대체가 일어나면 반드시 알린다.
    """
    if shutil.which(path):
        return path, None
    try:
        import config as project_config

        found = project_config.detect_tshark()
    except Exception:
        found = None
    if found and found != path:
        return found, f"지정한 tshark({path}) 를 찾을 수 없어 {found} 로 대체한다."
    return path, None


def _fmt_stats(s, unit: str = "s") -> str:
    if s is None:
        return "-"
    return (
        f"median={s.median:+.6f}{unit}  IQR={s.iqr:.6f}{unit}  "
        f"min={s.min:+.6f}  max={s.max:+.6f}  n={s.n}"
    )


def main() -> int:
    args = build_parser().parse_args()
    dataset = Path(args.dataset)

    try:
        cfg, cfg_path = timesync.load_config(
            args.config, search_from=dataset, auto=not args.no_config
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    cli = {k: getattr(args, k, None) for k in USED_KEYS}
    opts = timesync.merge_options(cli, cfg)
    opts["tshark"], tshark_warning = _resolve_tshark(opts["tshark"])
    if tshark_warning:
        print(f"[!] {tshark_warning}", file=sys.stderr)
    # --print-config 는 사용자가 자기 설정 파일을 만드는 용도라 PSK 를 그대로 낸다.
    if args.print_config:
        json.dump({"timesync": opts}, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0

    # 결과 JSON 에는 2단계 전용 키(source/glob/pattern/apply_out)까지 통째로 보존해
    # 파일 하나를 두 단계가 공유하게 한다. 단 PSK 는 뺀다 — 기본 저장 위치가
    # 데이터셋 트리 안이라 공유되기 쉽고, 2단계는 PSK 를 쓰지 않는다.
    used = dict(opts)
    used["psk"] = None

    if not dataset.exists():
        print(f"ERROR: 디렉터리 없음: {dataset}", file=sys.stderr)
        return 2

    try:
        tz = timesync.resolve_tz(opts["tz"])
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # 측정은 수 분씩 걸린다. 다 끝내고 나서 쓰기에 실패하면 결과가 날아가므로
    # tshark 를 돌리기 전에 출력 경로를 만들 수 있는지 먼저 확인한다.
    out = Path(opts["offset_out"]) if opts["offset_out"] else dataset / "timesync_offset.json"
    existed = out.exists()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "a", encoding="utf-8"):
            pass
        if not existed:
            out.unlink()  # 확인용으로 만든 빈 파일은 남기지 않는다
    except OSError as exc:
        suggested = Path("/tmp") / f"{dataset.name}_timesync_offset.json"
        print(
            f"ERROR: 결과를 쓸 수 없다: {out} ({exc.strerror})\n"
            f"  데이터셋 디렉터리에 쓰기 권한이 없으면 -o 로 다른 경로를 주면 된다:\n"
            f"    -o {suggested}",
            file=sys.stderr,
        )
        return 2

    if opts["syslog"]:
        syslogs = [Path(opts["syslog"])]
    else:
        # 한 데이터셋에 1호기/2호기/3호기 처럼 여러 장비 로그가 있고, 그중 일부만
        # 캡처 구간과 겹치는 경우가 있다. 전부 후보로 두고 pcap 별로 가장 잘 맞는
        # 것을 고른다.
        syslogs = timesync.find_syslogs(dataset)
    syslogs = [p for p in syslogs if p.exists()]
    if not syslogs:
        print(
            f"ERROR: sys.log 를 찾지 못했다 ({dataset}). --syslog 로 직접 지정하라.",
            file=sys.stderr,
        )
        return 2

    event_sets: list[tuple[str, list]] = []
    for p in syslogs:
        evs = timesync.parse_sync_events(p, pattern=opts["sync_pattern"], tz=tz)
        if evs:
            event_sets.append((str(p), evs))
    if not event_sets:
        names = ", ".join(str(p) for p in syslogs)
        print(
            f"ERROR: 동기화 이벤트를 찾지 못했다 ({names}) "
            f"(패턴: {opts['sync_pattern']!r}). --sync-pattern 을 조정하라.",
            file=sys.stderr,
        )
        return 1
    # 사람이 읽는 요약용 대표값 (가장 이벤트가 많은 로그)
    syslog, events = max(event_sets, key=lambda kv: len(kv[1]))

    pcaps = [Path(p) for p in opts["pcap"]] if opts["pcap"] else timesync.find_pcaps(dataset)
    if not pcaps:
        print(f"ERROR: pcap 을 찾지 못했다: {dataset}", file=sys.stderr)
        return 2

    if not args.quiet:
        if cfg_path:
            print(f"[*] 설정 파일    : {cfg_path}")
        if len(event_sets) == 1:
            print(f"[*] sys.log      : {syslog}")
        else:
            print(f"[*] sys.log 후보 : {len(event_sets)}개 (pcap 별로 가장 잘 맞는 것을 고른다)")
            for lbl, evs in event_sets:
                print(f"      {lbl}  ({len(evs)}건)")
        print(f"[*] 로그 타임존  : {opts['tz'] or '시스템 로컬 (' + str(datetime.now().astimezone().tzname()) + ')'}")
        print(
            f"[*] 동기화 이벤트: {len(events)}건 "
            f"({datetime.fromtimestamp(events[0].ts, tz):%H:%M:%S} ~ "
            f"{datetime.fromtimestamp(events[-1].ts, tz):%H:%M:%S})"
        )
        print(f"[*] pcap 후보    : {len(pcaps)}개"
              f"{'  (WPA 복호화 켜짐)' if opts['ssid'] and opts['psk'] else ''}")
        print()

    results = []
    for pcap in pcaps:
        if not args.quiet:
            print(f"--- {pcap} ---", flush=True)
        try:
            res = timesync.measure_offset_best(
                pcap,
                event_sets,
                tshark_path=opts["tshark"],
                ssid=opts["ssid"],
                passphrase=opts["psk"],
                tolerance=opts["tolerance"],
                tz=tz,
            )
        except (RuntimeError, OSError) as exc:
            # --quiet 여도 실패 진단은 삼키면 안 된다.
            print(f"[!] 건너뜀 ({pcap}): {exc}", file=sys.stderr)
            continue
        results.append(res)
        if args.quiet:
            continue
        print(f"    NTP mode4 프레임 : {res.ntp_responses}")
        if res.method == "ntp-only":
            print(f"    sys.log 매칭     : 없음 → NTP 프레임 {res.ntp_responses}건 전체 사용")
        else:
            n_ev = dict((lbl, len(e)) for lbl, e in event_sets).get(res.syslog, len(events))
            used = f"  ({Path(res.syslog).parent.name})" if len(event_sets) > 1 and res.syslog else ""
            print(f"    sys.log 매칭     : {res.matched}/{n_ev}{used}")
        if res.residual:
            print(f"    매칭 잔차        : {_fmt_stats(res.residual)}")
        if res.capture_minus_ntp:
            print(f"    캡처 - NTP서버   : {_fmt_stats(res.capture_minus_ntp)}")
        if res.device_minus_ntp_upper:
            print(f"    장치로그 - NTP서버: {_fmt_stats(res.device_minus_ntp_upper)}  (상한)")
        if res.drift_ppm is not None:
            print(f"    드리프트         : {res.drift_ppm:+.2f} ppm")
        if res.log_shift_seconds is not None:
            print(f"    => log_shift     : {res.log_shift_seconds:+.6f} s")
        print()

    # 경고는 --quiet 여부와 무관하게 stderr 로도 낸다.
    for res in results:
        for w in res.warnings:
            print(f"[!] {Path(res.pcap).name}: {w}", file=sys.stderr)
        for w in res.log_warnings:
            print(f"[!로그전용] {Path(res.pcap).name}: {w}", file=sys.stderr)
        for n in res.notes:
            print(f"[i] {Path(res.pcap).name}: {n}", file=sys.stderr)

    usable = [r for r in results if r.log_shift_seconds is not None]
    payload = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset": str(dataset),
        "syslog": str(syslog),
        "sync_events": len(events),
        "config_file": str(cfg_path) if cfg_path else None,
        # 이 블록을 그대로 --config 로 되먹일 수 있다.
        "options": used,
        "sources": [r.as_dict() for r in results],
    }

    try:
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: 결과 저장 실패 ({out}): {exc.strerror}", file=sys.stderr)
        print("측정 결과를 잃지 않도록 stdout 으로 대신 출력한다.", file=sys.stderr)
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 1

    if not args.quiet:
        print(f"[*] 저장: {out}")
        if not usable:
            print("[!] 오프셋을 산출한 pcap 이 없다. --ssid/--psk 또는 --tolerance 를 확인하라.")
        else:
            shifts = [r.log_shift_seconds for r in usable]
            print()
            print(f"[*] 오프셋을 산출한 소스 {len(usable)}개:")
            for r in usable:
                print(
                    f"      {r.log_shift_seconds:+14.6f} s  n={r.matched:<4}"
                    f"IQR={r.capture_minus_ntp.iqr * 1000:6.1f}ms   {Path(r.pcap).name}"
                )
            spread = max(shifts) - min(shifts) if len(usable) > 1 else 0.0
            # 이미 보정된 캡처들을 재측정하면 spread 가 0 에 수렴한다 — 그때는
            # 고를 것이 없으므로 경고하지 않는다.
            if spread > _SPREAD_WARN:
                print(
                    f"    [!] 소스별 오프셋이 {spread:.3f}s 벌어져 있다. 로그를 어느 캡처의 "
                    "타임라인에 맞출지는"
                )
                print(
                    "        통계가 아니라 분석 목적이 정한다 — --source 로 직접 고르라 "
                    "(자동 선택하지 않는다)."
                )
            print()
            # 로그 디렉터리는 실제로 채택된 sys.log 가 있는 곳이다
            # ('1호기' 를 가정하지 않는다 — 데이터셋에 여러 장비가 있을 수 있다).
            chosen = next((r.syslog for r in usable if r.syslog), syslog)
            logdir = Path(chosen).parent
            # 데이터셋 옆에 쓸 수 없으면(root 소유 등) /tmp 로 안내한다.
            preferred = dataset.parent / f"{dataset.name}_shifted"
            if not os.access(dataset.parent, os.W_OK):
                preferred = Path("/tmp") / f"{dataset.name}_shifted"
            script = Path(__file__).resolve().parent / "timesync-apply.py"
            try:
                script = script.relative_to(Path.cwd())
            except ValueError:
                pass
            print("[*] 2단계:")
            print(f'    python3 {script} "{logdir}" \\')
            print(f'        --config "{out}" --source "<위에서 고른 이름>" \\')
            print(f'        --out "{preferred / logdir.name}"')
    return 0 if usable else 1


if __name__ == "__main__":
    sys.exit(main())
