"""디버그 모드 공유 시간축 빌더 테스트."""
from analyzer.web.timeline_axis import (
    bin_index_for,
    build_time_axis,
    collect_epochs,
    iter_epochs,
)


class TestIterEpochs:
    def test_extracts_from_floats(self):
        assert list(iter_epochs([1000.0, 1001.5, 1002.0])) == [1000.0, 1001.5, 1002.0]

    def test_extracts_from_epoch_dicts(self):
        series = [{"epoch": 1000.0, "rssi": -60}, {"epoch": 1001.0, "rssi": -62}]
        assert list(iter_epochs(series)) == [1000.0, 1001.0]

    def test_extracts_multiple_keys_from_roaming_seq(self):
        # roaming sequence는 한 항목에 auth/assoc 두 시점을 갖는다 — 둘 다 방출.
        series = [{"auth_epoch": 1005.0, "assoc_epoch": 1005.2}]
        assert list(iter_epochs(series)) == [1005.0, 1005.2]

    def test_skips_bool_and_missing(self):
        series = [{"other": 1}, {"epoch": True}, {"epoch": 1000.0}]
        assert list(iter_epochs(series)) == [1000.0]


class TestBuildTimeAxis:
    def test_empty_sources(self):
        axis = build_time_axis([])
        assert axis["empty"] is True
        assert axis["bin_count"] == 0
        assert axis["bins"] == []

    def test_axis_spans_global_min_and_max(self):
        # 세 개의 서로 다른 소스 — 서로 다른 epoch 키와 범위.
        rssi = [{"epoch": 1002.0, "rssi": -60}, {"epoch": 1005.0, "rssi": -61}]
        ping = [{"epoch": 1000.0, "rtt_ms": 5.0}, {"epoch": 1009.0, "rtt_ms": 6.0}]
        roaming = [{"auth_epoch": 1004.0, "assoc_epoch": 1004.3}]
        axis = build_time_axis([rssi, ping, roaming])
        # 축의 start/end는 전 소스의 전역 min/max와 정확히 일치해야 한다.
        assert axis["start"] == 1000.0  # ping의 최소
        assert axis["end"] == 1009.0    # ping의 최대
        assert axis["duration_sec"] == 9.0
        assert axis["empty"] is False

    def test_bins_cover_full_window(self):
        rssi = [{"epoch": 1000.0}, {"epoch": 1010.0}]
        axis = build_time_axis([rssi], bin_count=10)
        assert axis["bin_count"] == 10
        assert len(axis["bins"]) == 10
        # 첫 bin은 start, 마지막 bin 왼쪽 경계 + bin_size == end.
        assert axis["bins"][0] == axis["start"]
        last_left = axis["bins"][-1]
        assert abs((last_left + axis["bin_size_sec"]) - axis["end"]) < 1e-9

    def test_explicit_bin_size(self):
        src = [{"epoch": 1000.0}, {"epoch": 1005.0}]
        axis = build_time_axis([src], bin_size_sec=1.0)
        assert axis["bin_size_sec"] == 1.0
        assert axis["bin_count"] == 5

    def test_single_point_window(self):
        axis = build_time_axis([[{"epoch": 1000.0}]])
        assert axis["start"] == axis["end"] == 1000.0
        assert axis["bin_count"] == 1
        assert axis["bins"] == [1000.0]

    def test_default_target_bins(self):
        src = [{"epoch": 0.0}, {"epoch": 120.0}]
        axis = build_time_axis([src])
        assert axis["bin_count"] == 60
        assert axis["bin_size_sec"] == 2.0


class TestAlignSourcesToSameScale:
    def test_different_sources_map_onto_same_grid(self):
        # 공유 축을 만든 뒤 서로 다른 소스의 같은 시각이 같은 bin에 떨어져야 한다
        # (= 같은 스케일로 정렬됨).
        rssi = [{"epoch": 1000.0}, {"epoch": 1009.0}]
        ping = [{"epoch": 1004.5, "rtt_ms": 5.0}]
        roaming = [{"auth_epoch": 1004.5}]
        axis = build_time_axis([rssi, ping, roaming], bin_count=10)

        # bin_size = 0.9초. epoch 1004.5는 (1004.5-1000)/0.9 = 5.0 → bin 5.
        ping_bin = bin_index_for(axis, 1004.5)
        roam_bin = bin_index_for(axis, 1004.5)
        assert ping_bin == roam_bin  # 같은 시각 → 같은 bin (정렬됨)
        assert ping_bin == 5

    def test_bin_index_clamped_within_axis(self):
        axis = build_time_axis([[{"epoch": 1000.0}, {"epoch": 1010.0}]], bin_count=10)
        # 축 범위 밖 epoch은 양 끝 bin으로 clamp.
        assert bin_index_for(axis, 990.0) == 0
        assert bin_index_for(axis, 9999.0) == axis["bin_count"] - 1
        assert bin_index_for(axis, 1000.0) == 0

    def test_endpoints_land_in_first_and_last_bins(self):
        axis = build_time_axis([[{"epoch": 1000.0}, {"epoch": 1010.0}]], bin_size_sec=1.0)
        assert bin_index_for(axis, axis["start"]) == 0
        assert bin_index_for(axis, axis["end"]) == axis["bin_count"] - 1

    def test_collect_epochs_across_sources(self):
        epochs = collect_epochs([[1000.0], [{"epoch": 1001.0}], None])
        assert sorted(epochs) == [1000.0, 1001.0]
