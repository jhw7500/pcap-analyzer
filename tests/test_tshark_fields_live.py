"""TSHARK_FIELDS의 모든 필드가 현재 호스트 tshark에서 실제로 인식되는지 검증.

회귀 방지 (2026-05-12):
- _ws.col.Protocol이 capability detection에서 false negative로 dropped된 이슈
- TSHARK_FIELDS와 build_tshark_cmd 사이의 silent drift 방지

@pytest.mark.slow + @pytest.mark.tshark — fixture pcap이 작아도 25+ 필드를
개별 tshark 호출하므로 1~2초 소요. tshark 없는 환경에선 skip.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from analyzer.core.extractor import TSHARK_FIELDS, _filter_unsupported_fields

pytestmark = [pytest.mark.slow, pytest.mark.tshark]


FIXTURE = Path(__file__).parent / "fixtures" / "sample_basic.pcap"


@pytest.fixture(scope="module")
def tshark_path():
    path = shutil.which("tshark")
    if path is None:
        pytest.skip("tshark not installed")
    return path


@pytest.fixture(scope="module")
def fixture_pcap():
    if not FIXTURE.exists():
        pytest.skip(f"fixture pcap not found: {FIXTURE}")
    return str(FIXTURE)


def test_every_tshark_field_is_accepted_by_local_tshark(tshark_path, fixture_pcap):
    """TSHARK_FIELDS의 모든 필드가 실제 tshark 호출에서 invalid field 에러를 내지 않아야 한다."""
    invalid = []
    for field in TSHARK_FIELDS:
        result = subprocess.run(
            [tshark_path, "-r", fixture_pcap, "-T", "fields", "-e", field, "-c", "1"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # tshark는 미지원 필드 시 stderr에 "Some fields aren't valid" 출력 + exit 1
        stderr = (result.stderr or "").lower()
        if result.returncode != 0 and "aren't valid" in stderr:
            invalid.append((field, result.stderr.strip()))

    if invalid:
        msg_lines = ["TSHARK_FIELDS의 다음 필드가 호스트 tshark에서 거부됨:"]
        for field, stderr in invalid:
            msg_lines.append(f"  - {field}: {stderr}")
        msg_lines.append(
            "\n조치: _filter_unsupported_fields 화이트리스트에 추가하거나 "
            "TSHARK_FIELDS에서 제거 후 parse_tsv_line 인덱스 조정."
        )
        pytest.fail("\n".join(msg_lines))


def test_capability_detection_does_not_falsely_drop_real_fields(tshark_path, fixture_pcap):
    """_filter_unsupported_fields가 실제로 tshark가 받는 필드를 drop하면 안 됨.

    회귀 방지: _ws.col.Protocol 처럼 -G fields 카탈로그에 없지만 실제로 accept되는
    column alias가 잘못 dropped되는 케이스를 잡는다.
    """
    used, dropped, _ = _filter_unsupported_fields(tshark_path)

    # dropped 필드 각각이 정말로 거부되는지 실 tshark 호출로 검증
    falsely_dropped = []
    for field in dropped:
        result = subprocess.run(
            [tshark_path, "-r", fixture_pcap, "-T", "fields", "-e", field, "-c", "1"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        stderr = (result.stderr or "").lower()
        is_really_rejected = result.returncode != 0 and "aren't valid" in stderr
        if not is_really_rejected:
            falsely_dropped.append(field)

    if falsely_dropped:
        pytest.fail(
            "capability detection이 다음 필드를 잘못 dropped로 판단함 "
            f"(실제 tshark는 인식): {falsely_dropped}\n"
            "조치: extractor.py의 화이트리스트 (_COLUMN_ALIAS_PREFIX 등)를 확장."
        )
