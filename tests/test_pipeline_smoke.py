"""실 fixture pcap으로 분석 파이프라인의 핵심 출력 sanity 검증.

회귀 방지 (2026-05-12):
- frame.protocol 컬럼이 누락되면 overview.protocol_dist가 비어버린 케이스
- Task 7 E2E는 HTTP 200만 봐서 분석 결과 품질은 못 잡았었음.

@pytest.mark.slow + @pytest.mark.tshark — tshark 없으면 skip.
"""
import shutil
from pathlib import Path

import pytest

from analyzer.pipeline import run_analysis

pytestmark = [pytest.mark.slow, pytest.mark.tshark]


FIXTURE = Path(__file__).parent / "fixtures" / "sample_basic.pcap"


@pytest.fixture(scope="module")
def fixture_pcap():
    if not FIXTURE.exists():
        pytest.skip(f"fixture pcap not found: {FIXTURE}")
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed")
    return str(FIXTURE)


def test_run_analysis_basic_outputs(fixture_pcap):
    """fixture pcap을 분석했을 때 핵심 출력이 비어있지 않아야 한다."""
    result = run_analysis(fixture_pcap)

    assert result.get("error") is None, f"분석 에러 발생: {result.get('error')}"
    assert result.get("frame_count", 0) > 0, "프레임이 하나도 추출되지 않음"

    overview = result.get("structured", {}).get("overview", {})
    assert overview, "structured.overview 자체가 비어있음 — pipeline 단계 누락"

    protocol_dist = overview.get("protocol_dist", {})
    assert protocol_dist, (
        "overview.protocol_dist가 비어있음 — frame.protocol 컬럼 누락 의심. "
        "_ws.col.Protocol이 capability detection에서 잘못 dropped됐을 가능성."
    )

    # protocol_dist는 최소 1개 이상의 protocol 카운트를 가져야 함
    total_proto_frames = sum(protocol_dist.values())
    assert total_proto_frames > 0, (
        f"protocol_dist의 값 합계가 0: {protocol_dist}"
    )
