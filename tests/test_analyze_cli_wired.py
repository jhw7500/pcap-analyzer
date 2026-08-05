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


def test_duplicate_wired_exits_2():
    """중복 --wired 지정은 에러로 거부."""
    p = _run("a.pcap", "ssid", "pw", "--wired", "w1.pcap", "--wired", "w2.pcap")
    assert p.returncode == 2
    assert "한 번만" in p.stderr


def test_usage_mentions_wireless():
    p = _run()
    assert p.returncode == 2
    assert "--wireless" in p.stderr


def test_wireless_without_value_exits_2():
    p = _run("a.pcap", "ssid", "pw", "--wireless")
    assert p.returncode == 2
    assert "wireless" in p.stderr


def test_repeated_wireless_collected_and_removed_from_argv():
    """--wireless 반복 지정은 모두 수집되고 argv에서 제거돼 positional 파싱에
    영향을 주지 않는다(중복 허용 — 가드 불요). run_analysis 도달 전 argument
    parsing 단계만 확인 — exit 2(usage 에러)가 아니면 파싱은 통과한 것."""
    p = _run("a.pcap", "ssid", "pw", "--wireless", "w2.pcap", "--wireless", "w3.pcap")
    assert p.returncode != 2
