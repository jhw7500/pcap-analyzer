"""이중 무선 캡처(TSF 오프셋·dedup) 골든 테스트.

tests/fixtures/sample_dual_a.pcap/sample_dual_b.pcap은
tests/fixtures/generate_sample_dual.py로 생성한 deterministic pcap 쌍이다.
A는 기준 시계, B는 2.5초 느린 시계로 같은 비콘 12개·ICMP 2쌍 중 1쌍을
공유한다 (자세한 구성은 generate_sample_dual.py docstring 참고).

tshark가 설치된 환경에서만 실행되므로 test_golden.py와 동일하게
@pytest.mark.slow + @pytest.mark.tshark로 격리한다.
"""
from collections import OrderedDict
from pathlib import Path
import shutil

import pytest

from analyzer.core.extractor import extract_frames
from analyzer.core.merge import merge_captures
from analyzer.pipeline import run_analysis

pytestmark = [pytest.mark.slow, pytest.mark.tshark]

FIXTURE_A = Path(__file__).parent / "fixtures" / "sample_dual_a.pcap"
FIXTURE_B = Path(__file__).parent / "fixtures" / "sample_dual_b.pcap"

# generate_sample_dual.py 설계값 — 생성기 상수와 1:1 대응
NUM_BEACONS = 12
NUM_SHARED_FRAMES = NUM_BEACONS + 2  # 비콘 12 + 공유 데이터 프레임 2개(req+rep)
TOTAL_INPUT_FRAMES = 15 + 15  # A 15프레임 + B 15프레임
EXPECTED_DUPLICATES = NUM_SHARED_FRAMES  # 14
EXPECTED_KEPT = TOTAL_INPUT_FRAMES - EXPECTED_DUPLICATES  # 16


def _skip_if_missing():
    if not (FIXTURE_A.exists() and FIXTURE_B.exists()):
        pytest.skip(f"fixture pcap not found: {FIXTURE_A} / {FIXTURE_B}")
    if shutil.which("tshark") is None:
        pytest.skip("tshark not installed")


@pytest.fixture(scope="module")
def result():
    _skip_if_missing()
    return run_analysis(str(FIXTURE_A), wireless_paths=[str(FIXTURE_B)])


@pytest.fixture(scope="module")
def merged_frames():
    """merge_captures 직접 호출 — Frame 레벨(ip_src, source)을 직접 검증하기 위함.

    run_analysis를 거치면 structured.ping 같은 상위 집계만 보여 대표 프레임
    교체가 실제로 일어났는지(우연히 같은 결과가 나온 건 아닌지) 구분할 수 없다.
    """
    _skip_if_missing()
    frames_a = extract_frames(str(FIXTURE_A))
    frames_b = extract_frames(str(FIXTURE_B))
    for f in frames_a:
        f.source = "w1"
    for f in frames_b:
        f.source = "w2"
    mr = merge_captures(OrderedDict([("w1", frames_a), ("w2", frames_b)]))
    return mr.frames


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
        """구조화 출력(ping) 레벨에서도 대표가 A쪽이었음을 간접 확인.

        B(암호화 사본)가 대표였다면 ip_src가 없어 RTT 매칭 자체가 안 됨.
        """
        stats = result["structured"]["ping"]["stats"]
        assert stats["rtt_matched"] >= 1
        assert stats["count"] >= 1

    def test_representative_is_decrypted_a_frame(self, merged_frames):
        """병합 결과의 공유 ICMP 프레임 대표를 Frame 레벨에서 직접 검증.

        생성기가 B의 공유 ICMP 프레임(request/reply)만 보정 후 A보다 10ms
        앞서도록 배치했다 — 그래서 정렬 순서상 B가 먼저 그룹을 만들고, A가
        나중에 도착해 _prefer_new_representative의 "ip_src 있는 쪽으로 교체"
        분기를 실제로 타야 이 값이 나온다. 이 분기가 깨지면(예: 무조건
        `return False`) 대표가 B(ip_src="")로 남아 아래 assert가 실패한다 —
        뮤테이션 테스트로 확인됨(fix report 참고).
        """
        # seq=2000은 생성기의 공유 ICMP request 전용 wlan.seq — A 단독 프레임(seq=3000)도
        # icmp_type="8"이라 seq로 구분하지 않으면 두 개가 섞인다.
        shared_req = [f for f in merged_frames if f.seq == "2000"]
        assert len(shared_req) == 1, f"공유 ICMP request가 dedup 후 정확히 1개여야 함: {shared_req}"
        rep = shared_req[0]
        assert rep.icmp_type == "8"
        assert rep.source == "w1"
        assert rep.ip_src == "192.168.1.100"
