"""run_analysis의 wireless_paths 통합 — 파일별 추출·태깅·merge·sources 부착."""
import os
import threading

import pytest

import config
import analyzer.pipeline as pipeline
from tests.conftest import make_frame, AP1

FILE_W1 = "w1.pcapng"
FILE_W2 = "w2.pcapng"

GT_OK = {
    "total": 100, "ok": 97, "ng": 3, "loss_pct": 3.0, "sender": "10.0.0.1",
    "targets": {"10.0.0.2": {"total": 100, "ng": 3}},
    "streaks": [{"target": "10.0.0.2", "start_epoch": 1004.5,
                 "end_epoch": 1006.5, "count": 3, "duration_sec": 2.0}],
    "ng_epochs": [1004.5, 1005.5, 1006.5], "trailing_dropped": 0, "warnings": [],
}


def _w1_frames():
    """비콘 12개(TSF 정렬용) + 데이터 1개(seq=200) — test_merge_dedup의
    test_offset_applied_before_dedup 픽스처(beac_a/dat_a) 재구성."""
    beac = [make_frame(number=i + 10, epoch=1000.0 + i * 0.1024, subtype="8", ta=AP1,
                       bssid=AP1, tsf=str(500_000 + i * 102400)) for i in range(12)]
    dat = make_frame(number=1, epoch=1001.000, seq="200", subtype="40")
    return beac + [dat]


def _w2_frames():
    """w1과 같은 비콘 12개(시계 -2s) + 같은 데이터1(-2s+5ms) + w2 단독 프레임 1개."""
    beac = [make_frame(number=i + 10, epoch=998.0 + i * 0.1024, subtype="8", ta=AP1,
                       bssid=AP1, tsf=str(500_000 + i * 102400)) for i in range(12)]
    dat = make_frame(number=1, epoch=999.005, seq="200", subtype="40")
    extra = make_frame(number=2, epoch=999.5, seq="999", subtype="40")
    return beac + [dat, extra]


def _patch_common(monkeypatch, gt, frames_by_path):
    def _extract(path, **kw):
        return frames_by_path[path]

    monkeypatch.setattr(pipeline, "extract_frames", _extract)
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", lambda *a, **kw: gt)
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)


def test_two_wireless_files_merged(monkeypatch):
    """extract_frames가 경로별로 다른 프레임 세트를 반환하도록 side_effect —
    결과 frames가 병합·dedup되고 sources가 파일별 2개."""
    frames_by_path = {FILE_W1: _w1_frames(), FILE_W2: _w2_frames()}
    _patch_common(monkeypatch, dict(GT_OK), frames_by_path)

    result = pipeline.run_analysis(FILE_W1, wireless_paths=[FILE_W2])

    sources = result["structured"]["sources"]
    wireless = [s for s in sources if s["role"] == "wireless"]
    assert len(wireless) == 2
    assert wireless[0]["applied_offset_ms"] == 0.0
    assert wireless[1]["applied_offset_ms"] == pytest.approx(2000.0, abs=1.0)
    assert wireless[0]["frame_count"] == 13   # w1 원본(dedup 전) 프레임 수
    assert wireless[1]["frame_count"] == 14   # w2 원본(dedup 전) 프레임 수
    assert result["structured"]["merge"]["duplicates"] == 13
    assert result["frame_count"] == 14  # 통합 후


def test_single_wireless_no_merge_key(monkeypatch):
    """단일 경로는 merge 키 없음 + 프레임 번호 원본 유지 (하위 호환)."""
    frames = _w1_frames()
    _patch_common(monkeypatch, dict(GT_OK), {FILE_W1: frames})

    result = pipeline.run_analysis(FILE_W1)

    assert "merge" not in result["structured"]
    assert [f.number for f in frames] == [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 1]
    assert result["frame_count"] == len(frames)


def test_extraction_cancelled_between_files(monkeypatch):
    """첫 파일 추출 후 cancel set → {"cancelled": True}, 두 번째 파일 추출 안 함."""
    cancel = threading.Event()
    calls = []

    def _extract(path, **kw):
        calls.append(path)
        if path == FILE_W1:
            cancel.set()
            return _w1_frames()
        raise AssertionError("두 번째 파일 추출이 호출되면 안 된다")

    monkeypatch.setattr(pipeline, "extract_frames", _extract)
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)

    result = pipeline.run_analysis(FILE_W1, wireless_paths=[FILE_W2], cancel_event=cancel)

    assert result == {"cancelled": True}
    assert calls == [FILE_W1]


def test_wireless_file_with_zero_frames_warned_and_skipped(monkeypatch):
    """스펙 §7: 무선 파일 wlan 프레임 0건 → 해당 파일 제외 + 경고. 전부 0건이면 error."""
    frames_by_path = {FILE_W1: _w1_frames(), FILE_W2: []}
    _patch_common(monkeypatch, dict(GT_OK), frames_by_path)

    result = pipeline.run_analysis(FILE_W1, wireless_paths=[FILE_W2])

    assert "error" not in result
    sources = result["structured"]["sources"]
    wireless = [s for s in sources if s["role"] == "wireless"]
    assert len(wireless) == 2
    assert wireless[1]["frame_count"] == 0
    assert wireless[1]["warnings"]
    # 살아남은 소스가 1개뿐이라 merge_captures 미호출 — 단일 경로와 동일 경로.
    assert "merge" not in result["structured"]
    assert result["frame_count"] == len(frames_by_path[FILE_W1])

    # 전부 0건이면 기존 NO_FRAMES error 경로 그대로.
    _patch_common(monkeypatch, dict(GT_OK), {FILE_W1: [], FILE_W2: []})
    result_all_zero = pipeline.run_analysis(FILE_W1, wireless_paths=[FILE_W2])
    assert result_all_zero == {
        "error": "프레임을 추출하지 못했습니다. tshark 경로 또는 pcap 파일을 확인하세요."
    }


def test_wired_gt_composes_with_multi_wireless(monkeypatch):
    """유선 GT(1단계)와 다중 무선이 동시 동작 — sources = w1, w2, wired 3항목."""
    frames_by_path = {FILE_W1: _w1_frames(), FILE_W2: _w2_frames()}
    _patch_common(monkeypatch, dict(GT_OK), frames_by_path)

    result = pipeline.run_analysis(
        FILE_W1, wireless_paths=[FILE_W2], wired_path="wired.pcapng"
    )

    sources = result["structured"]["sources"]
    assert [s["role"] for s in sources] == ["wireless", "wireless", "wired"]
    assert result["structured"]["ping"]["ground_truth"]["ng"] == 3
    assert "merge" in result["structured"]
