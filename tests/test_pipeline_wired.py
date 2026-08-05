"""run_analysis의 wired_path 통합 — sources·ground_truth 부착."""
import os
import threading

import config
import analyzer.pipeline as pipeline
from tests.conftest import make_frame, STA1, STA2, AP1

GT_OK = {
    "total": 100, "ok": 97, "ng": 3, "loss_pct": 3.0, "sender": "10.0.0.1",
    "targets": {"10.0.0.2": {"total": 100, "ng": 3}},
    "streaks": [{"target": "10.0.0.2", "start_epoch": 1004.5,
                 "end_epoch": 1006.5, "count": 3, "duration_sec": 2.0}],
    "ng_epochs": [1004.5, 1005.5, 1006.5], "trailing_dropped": 0, "warnings": [],
    "exchanges": [{"epoch": 1000.5, "target": "10.0.0.2", "rtt_ms": 1.5}],
    "rtt_stats": {"n": 1, "min_ms": 1.5, "avg_ms": 1.5, "max_ms": 1.5, "p95_ms": 1.5},
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
    assert ping["ground_truth"]["exchanges"] and ping["ground_truth"]["rtt_stats"]["n"] == 1
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


def test_upstream_topology_scopes_to_target_sta(monkeypatch):
    """상류 sender(유선 PC가 AP 너머의 STA를 ping) 캡처에서 무관 STA2의 로밍/재전송이
    유선 손실을 high로 둔갑시키지 않는다 — _structured_diagnosis가 signal["aps"]로
    ap_macs를 실제로 넘기는지까지 관통 검증한다(단위 테스트는 ap_macs를 직접 준다)."""
    def _upstream_frames():
        # detect_roles가 AP를 인식하려면 beacon이, STA로 세려면 그 MAC이 5프레임
        # 이상 등장해야 한다 — ap_macs 배선을 진짜로 태우려면 픽스처가 실제 role
        # 감지를 통과해야 하므로 그 조건을 갖춘다.
        return [
            make_frame(number=1, epoch=999.0, ta=AP1, ra="ff:ff:ff:ff:ff:ff",
                       subtype="8"),  # beacon → AP1이 AP로 감지된다
            # 다운링크 요청(AP→STA1): ip.src가 sender인데 송신자는 AP다
            make_frame(number=2, epoch=1000.0, ta=AP1, ra=STA1, subtype="40",
                       ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_type="8",
                       icmp_seq="1", seq="100"),
            # 업링크 응답(STA1→AP): ip.dst가 sender인데 수신자는 AP다
            make_frame(number=3, epoch=1000.005, ta=STA1, ra=AP1, subtype="40",
                       ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_type="0",
                       icmp_seq="1", seq="200"),
            make_frame(number=4, epoch=1001.0, ta=STA1, ra=AP1, subtype="40"),
            make_frame(number=5, epoch=1002.0, ta=AP1, ra=STA1, subtype="40"),
            # 무관한 STA2의 로밍 + 재전송 폭주 — 손실 창 안, 전부 같은 AP 경유
            make_frame(number=6, epoch=1005.0, ta=STA2, ra=AP1, subtype="11"),
            make_frame(number=7, epoch=1005.1, ta=STA2, ra=AP1, subtype="40", retry=True),
            make_frame(number=8, epoch=1005.2, ta=STA1, ra=AP1, subtype="40"),  # 대상 STA 정상
            make_frame(number=9, epoch=1005.3, ta=STA2, ra=AP1, subtype="40", retry=True),
            make_frame(number=10, epoch=1005.4, ta=STA2, ra=AP1, subtype="40", retry=True),
            make_frame(number=11, epoch=1005.45, ta=STA2, ra=AP1, subtype="40", retry=True),
            make_frame(number=12, epoch=1009.0, ta=STA1, ra=AP1, subtype="40"),
        ]

    monkeypatch.setattr(pipeline, "extract_frames", lambda *a, **kw: _upstream_frames())
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", lambda *a, **kw: dict(GT_OK))
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)

    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    issues = result["structured"]["diagnosis"]["issues"]
    wired = [i for i in issues if i.get("signal_type") == "wired_loss"]
    assert len(wired) == 1
    assert wired[0]["severity"] == "medium"          # STA2의 로밍/폭주는 대상 밖
    assert wired[0]["frame_refs"] == [8]             # 대상 STA1의 창 안 프레임만


def test_wired_cancel_reaches_run_analysis_result(monkeypatch):
    """유선 GT가 취소를 보고하면 전체 분석도 취소로 끝난다 — /api/cancel이 성공을
    보고했는데 결과는 정상 분석으로 남는 일이 없도록."""
    _patch_common(monkeypatch, {"cancelled": True})
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    assert result == {"cancelled": True}


def test_cancel_event_forwarded_to_build_ground_truth(monkeypatch):
    """취소 이벤트가 유선 GT까지 전달돼야 tshark 자식을 실제로 끊을 수 있다."""
    captured = {}
    cancel = threading.Event()

    def _fake_build_ground_truth(pcap_path, **kwargs):
        captured.update(kwargs)
        return dict(GT_OK)

    monkeypatch.setattr(pipeline, "extract_frames", lambda *a, **kw: _frames())
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", _fake_build_ground_truth)
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)

    pipeline.run_analysis(
        "wireless.pcapng", wired_path="wired.pcapng", cancel_event=cancel
    )
    assert captured["cancel_event"] is cancel


# --------------------------------------------------------------------------
# mac_filter 모집단 대칭 (PR #22 9라운드)
# --------------------------------------------------------------------------


def _capture_gt_kwargs(monkeypatch, frames=None):
    """build_ground_truth 호출 kwargs를 캡처하는 공통 셋업. 호출 안 되면 빈 dict."""
    captured = {}

    def _fake_build_ground_truth(pcap_path, **kwargs):
        captured["called"] = True
        captured.update(kwargs)
        return dict(GT_OK)

    monkeypatch.setattr(pipeline, "extract_frames",
                        lambda *a, **kw: frames if frames is not None else _frames())
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", _fake_build_ground_truth)
    monkeypatch.setattr(os.path, "getsize", lambda *a, **kw: 1000)
    return captured


def test_mac_filter_derives_equivalent_ip_filter(monkeypatch):
    """mac_filter로 무선이 특정 STA만 담으면 유선 GT도 같은 모집단을 봐야 한다 —
    mac_filter는 유선(비-802.11)에 MAC 개념이 없어 그대로 못 넘기므로, 이미 필터가
    적용된 무선 프레임의 IP로 동등한 ip_filter를 유도해 별도 인자(derived_ip_filter)로
    전달한다 (PR #22 11라운드 — 10라운드의 'ip_filter 대체' 방식에서 '병행 AND'로
    교체돼 사용자 ip_filter 자리는 항상 그대로 유지된다)."""
    captured = _capture_gt_kwargs(monkeypatch)
    pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng", mac_filter=STA1)
    # 이 픽스처는 STA1 자신이 ping을 보내는 직접 토폴로지 — 자기 IP는 10.0.0.1이다.
    assert captured["ip_filter"] == ""
    assert captured["derived_ip_filter"] == "10.0.0.1"


def test_mac_filter_derivation_excludes_wired_sender_ip(monkeypatch):
    """상류 토폴로지(유선 PC가 AP 너머 STA를 ping)에서 유도 목록에 sender IP까지
    섞이면 wired_ping의 '_filter_exchanges: sender가 필터에 있으면 전체 유지'
    경로를 타서 다른 target이 그대로 남는다 — 모집단이 다시 어긋난다. 대상 STA
    자신의 IP만 넘겨야 그 STA와의 ping만 남는다."""
    upstream = [
        make_frame(number=1, epoch=1000.0, ta=AP1, ra=STA1, subtype="40",
                   ip_src="10.0.0.1", ip_dst="10.0.0.2", icmp_type="8", icmp_seq="1"),
        make_frame(number=2, epoch=1000.005, ta=STA1, ra=AP1, subtype="40",
                   ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_type="0", icmp_seq="1"),
    ]
    captured = _capture_gt_kwargs(monkeypatch, frames=upstream)
    pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng", mac_filter=STA1)
    assert captured["ip_filter"] == ""
    assert captured["derived_ip_filter"] == "10.0.0.2"  # sender(10.0.0.1)는 넣지 않는다


def test_mac_filter_without_derivable_ips_skips_ground_truth(monkeypatch):
    """무선 프레임에 IP가 없으면(미해독 캡처 등) 동등 필터를 유도할 수 없다 —
    다른 모집단을 비교하느니 GT를 생략하고 경고한다."""
    no_ip = [make_frame(number=i, epoch=1000.0 + i, subtype="40") for i in range(1, 6)]
    captured = _capture_gt_kwargs(monkeypatch, frames=no_ip)
    result = pipeline.run_analysis(
        "wireless.pcapng", wired_path="wired.pcapng", mac_filter=STA1
    )
    assert not captured.get("called")  # 유선 분석 자체를 돌리지 않는다
    assert "ground_truth" not in result["structured"]["ping"]
    wired_src = result["structured"]["sources"][1]
    assert wired_src["role"] == "wired"
    assert any("유도할 수 없어" in w for w in wired_src["warnings"])


def test_no_mac_filter_does_not_derive_ip_filter(monkeypatch):
    """mac_filter가 없으면 기존 동작 그대로 — IP를 유도하지 않는다."""
    captured = _capture_gt_kwargs(monkeypatch)
    pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    assert captured["ip_filter"] == ""


def test_user_ip_filter_used_as_is_without_mac_filter(monkeypatch):
    """mac_filter가 없을 때만 사용자 ip_filter가 그대로 전달된다 — mac_filter가
    있으면(아래 test_mac_filter_and_ip_filter_combined_uses_derived) 유도값이
    우선한다 (PR #22 10라운드 — 기존 '사용자 ip_filter 우선' 테스트를 이 조건으로
    좁혔다)."""
    captured = _capture_gt_kwargs(monkeypatch)
    pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng",
                          ip_filter="10.0.0.2")
    assert captured["ip_filter"] == "10.0.0.2"


def test_mac_filter_and_ip_filter_combined_uses_derived(monkeypatch):
    """mac_filter와 ip_filter를 동시에 지정하면 무선은 두 필터의 AND(교집합)를
    본다 (PR #22 10라운드 — Finding A). **11라운드에서 기대값 조정**: 10라운드는
    유도값이 사용자 ip_filter를 '대체'하도록 구현했으나, 이는 직접 토폴로지에서
    사용자가 명시한 target 좁히기를 무력화하는 새 결함을 낳았다(11라운드 Finding A) —
    유도값(sender 자신의 IP)이 사용자의 target-only 필터를 덮어써 '전체 유지'
    경로를 타 버린다. 올바른 구조는 '대체'가 아니라 '병행(AND)': pipeline은 사용자
    ip_filter를 항상 그대로 전달하고, mac_filter 유도값은 별도 인자
    (derived_ip_filter)로 전달해 wired_ping이 두 필터를 독립적으로 순차 적용한다."""
    captured = _capture_gt_kwargs(monkeypatch)
    pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng",
                          mac_filter=STA1, ip_filter="10.0.0.99")
    # 사용자가 준 "10.0.0.99"는 그대로 유지되고, STA1의 유도값(직접 토폴로지
    # _frames() 기준 "10.0.0.1")은 별도 인자로 병행 전달된다.
    assert captured["ip_filter"] == "10.0.0.99"
    assert captured["derived_ip_filter"] == "10.0.0.1"


# --------------------------------------------------------------------------
# _derived_ip_filter 특수 IP 범위 (PR #22 10라운드 — Finding F)
# --------------------------------------------------------------------------


def test_derived_ip_filter_excludes_special_ip_ranges():
    """멀티캐스트·링크로컬·루프백·미지정 주소는 유도 대상에서 제외된다 —
    `analyzer.web.structured._is_special_ip`와 규칙을 통일했다. 이전에는
    0.0.0.0/255.255.255.255/'::'만 걸러 169.254.x.x(링크로컬)·127.x(루프백)가
    유도된 ip_filter에 섞여 들어갈 수 있었다."""
    frames = [
        make_frame(number=1, ta=STA1, ra=AP1, ip_src="169.254.1.1,10.0.0.5"),
        make_frame(number=2, ta=AP1, ra=STA1, ip_dst="127.0.0.1"),
        make_frame(number=3, ta=STA1, ra=AP1, ip_src="0.0.0.0"),
    ]
    assert pipeline._derived_ip_filter(frames, STA1) == "10.0.0.5"
