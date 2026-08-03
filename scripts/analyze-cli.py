"""CLI 분석 드라이버 — 웹 UI 없이 pipeline.run_analysis 호출."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.pipeline import run_analysis  # noqa: E402


def main():
    argv = sys.argv[1:]
    wired = ""
    if "--wired" in argv:
        i = argv.index("--wired")
        if i + 1 >= len(argv):
            print("ERROR: --wired 뒤에 유선 pcap 경로가 필요하다", file=sys.stderr)
            sys.exit(2)
        wired = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) < 3:
        print(
            "Usage: analyze-cli.py <pcap> <ssid> <passphrase> [out.json] [--wired wired.pcapng]",
            file=sys.stderr,
        )
        sys.exit(2)
    pcap, ssid, pw = argv[0], argv[1], argv[2]
    out = argv[3] if len(argv) >= 4 else None

    def _p(msg, pct):
        print(f"  [{pct:3d}%] {msg}", file=sys.stderr, flush=True)

    result = run_analysis(pcap, ssid=ssid, passphrase=pw, progress_cb=_p, wired_path=wired)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if out:
        Path(out).write_text(json.dumps(result, ensure_ascii=False, default=str), encoding="utf-8")
        print(f"saved: {out} ({Path(out).stat().st_size:,} bytes)", file=sys.stderr)
    else:
        # Windows 콘솔(cp949)에서 비-ASCII 결과 출력 시 UnicodeEncodeError 방지
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.flush()
            sys.stdout.reconfigure(encoding="utf-8")
        json.dump(result, sys.stdout, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
