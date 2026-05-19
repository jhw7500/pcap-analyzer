"""CLI 분석 드라이버 — 웹 UI 없이 pipeline.run_analysis 호출."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.pipeline import run_analysis  # noqa: E402


def main():
    if len(sys.argv) < 4:
        print("Usage: analyze-cli.py <pcap> <ssid> <passphrase> [out.json]", file=sys.stderr)
        sys.exit(2)
    pcap, ssid, pw = sys.argv[1], sys.argv[2], sys.argv[3]
    out = sys.argv[4] if len(sys.argv) >= 5 else None

    def _p(msg, pct):
        print(f"  [{pct:3d}%] {msg}", file=sys.stderr, flush=True)

    result = run_analysis(pcap, ssid=ssid, passphrase=pw, progress_cb=_p)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if out:
        Path(out).write_text(json.dumps(result, ensure_ascii=False, default=str))
        print(f"saved: {out} ({Path(out).stat().st_size:,} bytes)", file=sys.stderr)
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
