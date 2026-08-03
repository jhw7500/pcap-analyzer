"""run_analysis의 wired_path 통합 — sources·ground_truth 부착."""
import os
import config
import analyzer.pipeline as pipeline
from tests.conftest import make_frame, STA1, AP1

GT_OK = {
    "total": 100, "ok": 97, "ng": 3, "loss_pct": 3.0, "sender": "10.0.0.1",
    "targets": {"10.0.0.2": {"total": 100, "ng": 3}},
    "streaks": [{"target": "10.0.0.2", "start_epoch": 1004.5,
                 "end_epoch": 1006.5, "count": 3, "duration_sec": 2.0}],
    "ng_epochs": [1004.5, 1005.5, 1006.5], "trailing_dropped": 0, "warnings": [],
}


def _frames():
    # ICMP 쌍 포함 — ping 통계가 비지 않게. Auth(roaming)·retry 프레임은 Task 3 대조용.
    return [
        make_frame(number=1, epoch=1000.0, subtype="40", ip_src="10.0.0.1",
                   ip_dst="10.0.0.2", icmp_type="8", icmp_seq="1", seq="100"),
        make_frame(number=2, epoch=1000.005, ta=AP1, ra=STA1, subtype="40",
                   ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_type="0",
                   icmp_seq="1", seq="200"),
        make_frame(number=3, epoch=1005.0, subtype="11"),               # Auth
        make_frame(number=4, epoch=1005.5, subtype="40", retry=True),   # 재전송
        make_frame(number=5, epoch=1009.0, subtype="40"),
    ]


def _patch_common(monkeypatch, gt):
    monkeypatch.setattr(pipeline, "extract_frames", lambda *a, **kw: _frames())
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", lambda *a, **kw: gt)
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)


def test_wired_path_attaches_ground_truth_and_sources(monkeypatch):
    _patch_common(monkeypatch, dict(GT_OK))
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    ping = result["structured"]["ping"]
    assert ping["ground_truth"]["ng"] == 3
    sources = result["structured"]["sources"]
    assert [s["role"] for s in sources] == ["wireless", "wired"]
    assert sources[0]["frame_count"] == 5


def test_wired_error_becomes_source_warning(monkeypatch):
    _patch_common(monkeypatch, {"error": "무선(802.11) 캡처다 — 유선 캡처를 넣어라: x", "warnings": []})
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    assert "ground_truth" not in result["structured"]["ping"]
    wired_src = result["structured"]["sources"][1]
    assert any("무선" in w for w in wired_src["warnings"])


def test_no_wired_path_keeps_existing_shape(monkeypatch):
    _patch_common(monkeypatch, dict(GT_OK))
    result = pipeline.run_analysis("wireless.pcapng")
    assert "ground_truth" not in result["structured"]["ping"]
    sources = result["structured"]["sources"]
    assert len(sources) == 1 and sources[0]["role"] == "wireless"


def test_wired_loss_issue_reaches_diagnosis(monkeypatch):
    _patch_common(monkeypatch, dict(GT_OK))
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    issues = result["structured"]["diagnosis"]["issues"]
    wired = [i for i in issues if i.get("signal_type") == "wired_loss"]
    assert len(wired) == 1
    assert wired[0]["frame_refs"] == [3, 4]


def test_wired_filters_forwarded_to_build_ground_truth(monkeypatch):
    """time_start/time_end/ip_filter가 무선과 동일 구간을 보도록 유선 GT에도 전달된다."""
    captured = {}

    def _fake_build_ground_truth(pcap_path, **kwargs):
        captured["pcap_path"] = pcap_path
        captured.update(kwargs)
        return dict(GT_OK)

    monkeypatch.setattr(pipeline, "extract_frames", lambda *a, **kw: _frames())
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", _fake_build_ground_truth)
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)

    pipeline.run_analysis(
        "wireless.pcapng", wired_path="wired.pcapng",
        time_start="2026-01-01 10:00:00", time_end="2026-01-01 11:00:00",
        ip_filter="10.0.0.2",
    )
    assert captured["time_start"] == "2026-01-01 10:00:00"
    assert captured["time_end"] == "2026-01-01 11:00:00"
    assert captured["ip_filter"] == "10.0.0.2"
