"""analyze-cli.py --wired 인자 계약."""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "analyze-cli.py"


def _run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_usage_mentions_wired():
    p = _run()
    assert p.returncode == 2
    assert "--wired" in p.stderr


def test_wired_without_value_exits_2():
    p = _run("a.pcap", "ssid", "pw", "--wired")
    assert p.returncode == 2
    assert "wired" in p.stderr


def test_positional_contract_unchanged():
    """인자 2개면 여전히 usage 에러 (기존 계약)."""
    p = _run("a.pcap", "ssid")
    assert p.returncode == 2
