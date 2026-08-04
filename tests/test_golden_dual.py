"""이중 무선 캡처(TSF 오프셋·dedup) 골든 테스트.

tests/fixtures/sample_dual_a.pcap/sample_dual_b.pcap은
tests/fixtures/generate_sample_dual.py로 생성한 deterministic pcap 쌍이다.
A는 기준 시계, B는 2.5초 느린 시계로 같은 비콘 12개·ICMP 2쌍 중 1쌍을
공유한다 (자세한 구성은 generate_sample_dual.py docstring 참고).

tshark가 설치된 환경에서만 실행되므로 test_golden.py와 동일하게
@pytest.mark.slow + @pytest.mark.tshark로 격리한다.
"""
from pathlib import Path
import shutil

import pytest

from analyzer.pipeline import run_analysis

pytestmark = [pytest.mark.slow, pytest.mark.tshark]

FIXTURE_A = Path(__file__).parent / "fixtures" / "sample_dual_a.pcap"
FIXTURE_B = Path(__file__).parent / "fixtures" / "sample_dual_b.pcap"

# generate_sample_dual.py 설계값 — 생성기 상수와 1:1 대응
NUM_BEACONS = 12
NUM_SHARED_DATA = 1  # ICMP req/rep 쌍 — dedup 단위는 "쌍"이 아니라 "프레임" 2개
NUM_SHARED_FRAMES = NUM_BEACONS + 2  # 비콘 12 + 공유 데이터 프레임 2개(req+rep)
TOTAL_INPUT_FRAMES = 15 + 15  # A 15프레임 + B 15프레임
EXPECTED_DUPLICATES = NUM_SHARED_FRAMES  # 14
EXPECTED_KEPT = TOTAL_INPUT_FRAMES - EXPECTED_DUPLICATES  # 16


@pytest.fixture(scope="module")
def result():
    if not (FIXTURE_A.exists() and FIXTURE_B.exists()):
        pytest.skip(f"fixture pcap not found: {FIXTURE_A} / {FIXTURE_B}")
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed")
    return run_analysis(str(FIXTURE_A), wireless_paths=[str(FIXTURE_B)])


class TestGoldenDualCapture:
    def test_no_error(self, result):
        assert result.get("error") is None, f"분석 에러 발생: {result.get('error')}"

    def test_sources_two_wireless(self, result):
        sources = result["structured"]["sources"]
        assert len(sources) == 2
        assert sources[0]["role"] == "wireless"
        assert sources[1]["role"] == "wireless"
        assert sources[0]["offset_method"] == "reference"

    def test_offset_tsf_and_pairs(self, result):
        w2 = result["structured"]["sources"][1]
        assert w2["offset_method"] == "tsf"
        # B가 2.5s 느리므로 A - B 기준 보정값은 양수(+2500ms 근방)
        assert w2["applied_offset_ms"] == pytest.approx(2500.0, abs=50.0)
        assert w2["offset_pairs"] == NUM_BEACONS

    def test_merge_duplicates_and_coverage(self, result):
        merge = result["structured"]["merge"]
        assert merge["duplicates"] == EXPECTED_DUPLICATES
        assert merge["kept"] == EXPECTED_KEPT
        coverage = merge["coverage"]
        assert coverage["both"] == EXPECTED_DUPLICATES
        assert coverage["only"] == {"w1": 1, "w2": 1}

    def test_frame_count_after_dedup(self, result):
        assert result["frame_count"] == EXPECTED_KEPT

    def test_representative_prefers_decrypted_frame(self, result):
        """공유 ICMP 쌍의 대표 프레임은 IP 필드가 있는 A쪽이어야 한다.

        B는 동일 wlan.seq의 802.11 Data이지만 IP/ICMP가 없는(암호화된 것처럼
        구성된) 프레임이다 — dedup 대표 선정이 ip_src 유무를 우선하지 않으면
        ping 분석에 쓸 IP 필드가 소실된다 (analyzer/core/merge.py
        _prefer_new_representative 참고).
        """
        stats = result["structured"]["ping"]["stats"]
        # 대표가 암호화된 B쪽이었다면 ip_src가 없어 RTT 매칭 자체가 안 됨
        assert stats["rtt_matched"] >= 1
        assert stats["count"] >= 1
