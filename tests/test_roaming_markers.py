"""디버그 모드 roaming 이벤트 마커 추출/투영 테스트 (Sub-AC 5).

`roaming.extract_roaming_events`는 roaming.py의 탐지 규칙(서브타입 11/0/2, STA
송신)을 재사용해 Auth/Assoc/Reassoc 이벤트를 구조화해 뽑고,
`timeline_series.project_roaming_markers`는 그 이벤트들을 Sub-AC 1의 공유
시간축(build_time_axis) 위 개별 마커로 투영한다. 핵심 검증: 각 Auth/Reassoc
이벤트가 공유 축 위 '정확한 시간 위치'(bin/타임스탬프)에 매핑되며 RSSI/retry/ping
시계열과 같은 축에 정렬된다.
"""
from analyzer.core.modules.roaming import extract_roaming_events
from analyzer.web.timeline_axis import bin_index_for, build_time_axis
from analyzer.web.timeline_series import (
    project_rssi_series,
    project_roaming_markers,
)
from tests.conftest import AP1, STA1, STA2, SAMPLE_ROLES, make_frame


def _rssi(epoch, rssi):
    return {"epoch": epoch, "rssi": rssi, "mcs": None}


class TestExtractRoamingEvents:
    def test_extracts_auth_and_reassoc_kinds(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),  # Auth
            make_frame(number=2, epoch=1005.0, ta=STA1, ra=AP1, subtype="2"),   # Reassoc
            make_frame(number=3, epoch=1009.0, ta=STA1, ra=AP1, subtype="0"),   # Assoc
        ]
        events = extract_roaming_events(frames, SAMPLE_ROLES)
        assert [e["kind"] for e in events] == ["auth", "reassoc", "assoc"]
        # 캡처 순서 보존 + 이벤트별 정확한 epoch.
        assert [e["epoch"] for e in events] == [1000.0, 1005.0, 1009.0]

    def test_preserves_frame_number_as_evidence(self):
        frames = [
            make_frame(number=42, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),
            make_frame(number=77, epoch=1005.0, ta=STA1, ra=AP1, subtype="2"),
        ]
        events = extract_roaming_events(frames, SAMPLE_ROLES)
        # frame.number = 증거용 canonical frame id → 각 이벤트가 정확한 프레임을 가리킴.
        assert [e["frame_number"] for e in events] == [42, 77]
        assert events[0]["sta"] == STA1 and events[0]["ap"] == AP1

    def test_skips_ap_tx_and_non_roaming_and_other_subtypes(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),  # 유효 Auth
            make_frame(number=2, epoch=1001.0, ta=AP1, ra=STA1, subtype="1"),   # AssocResp(AP 송신) → skip
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, subtype="40"),  # Data(비-로밍) → skip
            make_frame(number=4, epoch=1003.0, ta=AP1, ra=STA1, subtype="2"),   # Reassoc지만 AP 송신 → skip
        ]
        events = extract_roaming_events(frames, SAMPLE_ROLES)
        assert len(events) == 1
        assert events[0]["kind"] == "auth"
        assert events[0]["frame_number"] == 1

    def test_empty_when_no_roaming_frames(self):
        frames = [make_frame(number=i, epoch=1000.0 + i, subtype="40") for i in range(5)]
        assert extract_roaming_events(frames, SAMPLE_ROLES) == []


class TestProjectRoamingMarkers:
    def test_empty_axis_returns_empty(self):
        axis = build_time_axis([])  # empty=True, bin_count=0
        events = [{"kind": "auth", "epoch": 1000.0, "frame_number": 1}]
        assert project_roaming_markers(events, axis) == []

    def test_empty_events_returns_empty(self):
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)
        assert project_roaming_markers([], axis) == []

    def test_each_event_maps_to_correct_timestamp_on_shared_axis(self):
        # 핵심 AC: 각 Auth/Reassoc 이벤트가 공유 축 위 '정확한 시간 위치'에 매핑.
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),  # Auth @1000 → bin0
            make_frame(number=2, epoch=1005.0, ta=STA1, ra=AP1, subtype="2"),   # Reassoc @1005 → bin5
            make_frame(number=3, epoch=1009.0, ta=STA1, ra=AP1, subtype="11"),  # Auth @1009 → bin9
        ]
        events = extract_roaming_events(frames, SAMPLE_ROLES)
        # 공유 축: 1000~1010, bin_size=1.0 → 10 bins.
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_size_sec=1.0)
        markers = project_roaming_markers(events, axis)

        assert [m["bin"] for m in markers] == [0, 5, 9]
        for m in markers:
            # 마커는 이벤트의 실제 epoch(정확한 timestamp)을 보존.
            # bin 인덱스는 그 epoch을 공유 축 매핑(bin_index_for)한 값과 정확히 일치.
            assert bin_index_for(axis, m["epoch"]) == m["bin"]
            # bin_epoch은 해당 bin의 왼쪽 경계(축 그리드에 정렬).
            assert m["bin_epoch"] == axis["bins"][m["bin"]]
        # 이벤트의 실제 시각이 그대로 보존됨.
        assert [m["epoch"] for m in markers] == [1000.0, 1005.0, 1009.0]

    def test_markers_align_to_rssi_series_bins(self):
        # roaming 마커가 RSSI 시계열과 '같은 축 bin'에 정렬되는지 검증.
        epochs = [1000.0, 1003.0, 1006.0, 1009.0]
        frames = [
            make_frame(number=i + 1, epoch=e, ta=STA1, ra=AP1, subtype="11")
            for i, e in enumerate(epochs)
        ]
        events = extract_roaming_events(frames, SAMPLE_ROLES)
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)

        rssi_pts = project_rssi_series([_rssi(e, -60) for e in epochs], axis)
        markers = project_roaming_markers(events, axis)

        # 같은 axis·같은 epoch → 동일한 bin 인덱스 시퀀스.
        assert [m["bin"] for m in markers] == [p["bin"] for p in rssi_pts]
        # 마커의 bin_epoch이 RSSI 포인트의 (그리드 정렬) epoch과 동일.
        assert [m["bin_epoch"] for m in markers] == [p["epoch"] for p in rssi_pts]

    def test_markers_are_time_ordered(self):
        # 입력을 시간 역순으로 줘도 출력 마커는 epoch 오름차순.
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)
        events = [
            {"kind": "auth", "epoch": 1009.0, "frame_number": 3},
            {"kind": "reassoc", "epoch": 1001.0, "frame_number": 1},
            {"kind": "auth", "epoch": 1005.0, "frame_number": 2},
        ]
        markers = project_roaming_markers(events, axis)
        epochs = [m["epoch"] for m in markers]
        bins = [m["bin"] for m in markers]
        assert epochs == sorted(epochs)
        assert bins == sorted(bins)

    def test_each_event_kept_as_individual_marker_not_bucketed(self):
        # 한 bin 안에 여러 roaming 이벤트가 떨어져도 버킷팅하지 않고 개별 마커로 유지.
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_size_sec=10.0)
        assert axis["bin_count"] == 1
        events = [
            {"kind": "auth", "epoch": 1001.0, "frame_number": 1},
            {"kind": "reassoc", "epoch": 1004.0, "frame_number": 2},
            {"kind": "auth", "epoch": 1007.0, "frame_number": 3},
        ]
        markers = project_roaming_markers(events, axis)
        assert len(markers) == 3  # 집계되지 않음
        assert all(m["bin"] == 0 for m in markers)
        # 증거용 frame.number가 각 마커마다 보존됨.
        assert [m["frame_number"] for m in markers] == [1, 2, 3]
        assert [m["kind"] for m in markers] == ["auth", "reassoc", "auth"]

    def test_skips_events_with_missing_none_or_bool_epoch(self):
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_size_sec=10.0)
        dirty = [
            {"kind": "auth", "frame_number": 1},                 # epoch 없음 → skip
            {"kind": "auth", "epoch": None, "frame_number": 2},  # epoch None → skip
            {"kind": "auth", "epoch": True, "frame_number": 3},  # epoch bool → skip
            {"kind": "reassoc", "epoch": 1003.0, "frame_number": 4},  # 유효
        ]
        markers = project_roaming_markers(dirty, axis)
        assert len(markers) == 1
        assert markers[0]["frame_number"] == 4
        assert markers[0]["kind"] == "reassoc"

    def test_out_of_range_events_clamped_to_end_bins(self):
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)
        events = [
            {"kind": "auth", "epoch": 990.0, "frame_number": 1},    # 범위 이전 → bin0
            {"kind": "auth", "epoch": 9999.0, "frame_number": 2},   # 범위 이후 → 마지막 bin
        ]
        markers = project_roaming_markers(events, axis)
        bins = {m["bin"] for m in markers}
        assert bins == {0, axis["bin_count"] - 1}

    def test_end_to_end_extract_then_project(self):
        # extract → project 파이프라인: 추출된 이벤트가 그대로 마커로 투영됨.
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),
            make_frame(number=2, epoch=1002.0, ta=AP1, ra=STA1, subtype="1"),   # AP 송신 → 추출 제외
            make_frame(number=3, epoch=1004.0, ta=STA2, ra=AP1, subtype="2"),   # STA2 Reassoc
        ]
        events = extract_roaming_events(frames, SAMPLE_ROLES)
        axis = build_time_axis([events], bin_size_sec=1.0)
        markers = project_roaming_markers(events, axis)
        assert len(markers) == 2
        assert [m["frame_number"] for m in markers] == [1, 3]
        assert [m["sta"] for m in markers] == [STA1, STA2]
        for m in markers:
            assert bin_index_for(axis, m["epoch"]) == m["bin"]
