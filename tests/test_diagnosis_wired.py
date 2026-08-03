"""유선 확정 손실 구간 ↔ 무선 이벤트 대조 이슈."""
from analyzer.web.structured import _ground_truth_issue_candidates
from tests.conftest import make_frame

GT = {"streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                   "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}


def test_candidate_with_roaming_and_retry_evidence():
    frames = [
        make_frame(number=1, epoch=1004.0, subtype="11"),              # Auth — 창(±2s) 안
        make_frame(number=2, epoch=1005.5, subtype="40", retry=True),  # 재전송 — 창 안
        make_frame(number=3, epoch=1030.0, subtype="40"),              # 창 밖
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["refs"] == [1, 2]
    assert c["window"] == {"start_epoch": 1003.0, "end_epoch": 1008.0}
    assert c["signal_type"] == "wired_loss"
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"] and "재전송 1건" in c["issue"]["msg"]


def test_candidate_without_anomaly_uses_normal_traffic_as_refs():
    """이상 징후가 없으면 구간 내 일반 프레임을 근거로 '무선 외 원인 가능성' 이슈."""
    frames = [make_frame(number=7, epoch=1005.2, subtype="40")]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    assert cands[0]["refs"] == [7]
    assert "이상 징후 없음" in cands[0]["issue"]["msg"]


def test_no_frames_in_window_drops_candidate():
    """구간에 무선 프레임이 아예 없으면(캡처 구멍) 근거를 못 대므로 후보 없음."""
    frames = [make_frame(number=9, epoch=2000.0)]
    assert _ground_truth_issue_candidates(GT, frames) == []


def test_empty_ground_truth_no_candidates():
    assert _ground_truth_issue_candidates({}, [make_frame()]) == []
    assert _ground_truth_issue_candidates({"streaks": []}, []) == []
