"""디버그 모드 RSSI 시계열 투영(projection) 테스트.

`project_rssi_series`는 RSSI 샘플들을 Sub-AC 1의 공유 시간축(build_time_axis) 위
bin으로 버킷팅해, **시간순으로 정렬되고 축 그리드에 정렬된** 포인트 리스트를
만든다(대용량 캡처 다운샘플링 포함).
"""
from analyzer.web.timeline_axis import bin_index_for, build_time_axis
from analyzer.web.timeline_series import (
    project_ping_series,
    project_retry_series,
    project_rssi_series,
)


def _rssi(epoch, rssi):
    # structured.py의 rssi_timeline 항목 형태와 동일.
    return {"epoch": epoch, "rssi": rssi, "mcs": None}


def _frame(epoch, retry):
    # Frame(.epoch, .retry=bool) per-frame 행 형태와 동일.
    return {"epoch": epoch, "retry": retry}


def _success(epoch):
    # ping_matching.py가 만드는 양방향 매칭(성공) outcome 형태와 동일.
    return {"epoch": epoch, "status": "matched", "rtt_ms": 5.0}


def _loss(epoch, status="loss"):
    # ping_matching.py의 확정 손실("loss") / seq-gap 손실("loss_gap") outcome 형태.
    return {"epoch": epoch, "status": status, "rtt_ms": None}


class TestProjectRssiSeriesAlignment:
    def test_empty_axis_returns_empty(self):
        axis = build_time_axis([])  # empty=True, bin_count=0
        assert project_rssi_series([_rssi(1000.0, -60)], axis) == []

    def test_empty_samples_returns_empty(self):
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)
        assert project_rssi_series([], axis) == []

    def test_points_are_time_ordered(self):
        samples = [_rssi(1000.0, -60), _rssi(1010.0, -61)]
        axis = build_time_axis([samples], bin_count=10)
        # 입력을 일부러 시간 역순으로 섞어도 출력은 시간순이어야 한다.
        shuffled = [_rssi(1009.0, -65), _rssi(1001.0, -55), _rssi(1005.0, -58)]
        points = project_rssi_series(shuffled, axis)
        bins = [p["bin"] for p in points]
        epochs = [p["epoch"] for p in points]
        assert bins == sorted(bins)
        assert epochs == sorted(epochs)

    def test_points_aligned_to_axis_grid(self):
        samples = [_rssi(1000.0, -60), _rssi(1010.0, -61)]
        axis = build_time_axis([samples], bin_count=10)
        points = project_rssi_series(
            [_rssi(1001.0, -55), _rssi(1004.5, -58), _rssi(1009.0, -65)], axis
        )
        for p in points:
            # bin 인덱스는 축 범위 안.
            assert 0 <= p["bin"] < axis["bin_count"]
            # epoch은 정확히 해당 bin의 왼쪽 경계(축 그리드에 정렬).
            assert p["epoch"] == axis["bins"][p["bin"]]
            # bin_index_for로 다시 매핑해도 같은 bin (정렬 일관성).
            assert bin_index_for(axis, p["epoch"]) == p["bin"]

    def test_same_bin_samples_are_bucketed_and_averaged(self):
        # 한 bin 안에 떨어지는 여러 샘플은 하나의 포인트로 집계(평균)된다.
        samples = [_rssi(1000.0, -60), _rssi(1010.0, -60)]
        axis = build_time_axis([samples], bin_size_sec=10.0)  # 1 bin
        assert axis["bin_count"] == 1
        points = project_rssi_series(
            [_rssi(1000.0, -50), _rssi(1002.0, -60), _rssi(1004.0, -70)], axis
        )
        assert len(points) == 1
        p = points[0]
        assert p["bin"] == 0
        assert p["count"] == 3
        assert p["rssi"] == -60.0  # (-50 + -60 + -70) / 3
        assert p["rssi_min"] == -70
        assert p["rssi_max"] == -50

    def test_distinct_bins_yield_distinct_points(self):
        samples = [_rssi(1000.0, -60), _rssi(1010.0, -61)]
        axis = build_time_axis([samples], bin_size_sec=1.0)  # 10 bins
        points = project_rssi_series(
            [_rssi(1000.0, -50), _rssi(1005.0, -60), _rssi(1009.0, -70)], axis
        )
        assert [p["bin"] for p in points] == [0, 5, 9]
        assert [p["rssi"] for p in points] == [-50.0, -60.0, -70.0]

    def test_skips_missing_none_and_bool_values(self):
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)
        dirty = [
            {"epoch": 1000.0},            # rssi 없음 → skip
            {"epoch": 1001.0, "rssi": None},  # rssi None → skip
            {"epoch": 1002.0, "rssi": True},  # bool → skip
            {"rssi": -55},                # epoch 없음 → skip
            {"epoch": None, "rssi": -55},     # epoch None → skip
            _rssi(1003.0, -58),           # 유효
        ]
        points = project_rssi_series(dirty, axis)
        assert len(points) == 1
        assert points[0]["rssi"] == -58.0
        assert points[0]["count"] == 1

    def test_out_of_range_samples_clamped_to_end_bins(self):
        axis = build_time_axis([[_rssi(1000.0, -60), _rssi(1010.0, -61)]], bin_count=10)
        points = project_rssi_series(
            [_rssi(990.0, -50), _rssi(9999.0, -80)], axis
        )
        bins = {p["bin"] for p in points}
        assert bins == {0, axis["bin_count"] - 1}

    def test_large_capture_is_downsampled_to_bin_count(self):
        # 수많은 샘플도 출력 포인트 수는 bin_count 이하로 다운샘플된다.
        axis = build_time_axis([[_rssi(0.0, -60), _rssi(100.0, -60)]], bin_count=50)
        many = [_rssi(i * 0.01, -60 - (i % 10)) for i in range(10000)]
        points = project_rssi_series(many, axis)
        assert len(points) <= axis["bin_count"]
        # 여전히 시간순.
        assert [p["bin"] for p in points] == sorted(p["bin"] for p in points)


class TestProjectRetrySeriesAlignment:
    def test_empty_axis_returns_empty(self):
        axis = build_time_axis([])  # empty=True, bin_count=0
        assert project_retry_series([_frame(1000.0, True)], axis) == []

    def test_empty_frames_returns_empty(self):
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_count=10)
        assert project_retry_series([], axis) == []

    def test_retry_bins_align_to_rssi_series_bins(self):
        # 핵심 AC: retry 값이 RSSI 시계열과 '같은 축 bin'에 정렬되는지 검증한다.
        # 동일한 공유 축 위에서 같은 epoch의 retry/RSSI 샘플은 같은 bin·같은
        # bin-경계 epoch을 가져야 한다.
        epochs = [1000.0, 1003.0, 1006.0, 1009.0]
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_count=10)

        rssi_pts = project_rssi_series([_rssi(e, -60) for e in epochs], axis)
        retry_pts = project_retry_series([_frame(e, True) for e in epochs], axis)

        # 같은 axis·같은 epoch → 같은 bin 인덱스 시퀀스.
        assert [p["bin"] for p in retry_pts] == [p["bin"] for p in rssi_pts]
        # 같은 bin-경계 epoch (축 그리드에 동일 정렬).
        assert [p["epoch"] for p in retry_pts] == [p["epoch"] for p in rssi_pts]
        # 각 retry 포인트의 bin/epoch이 RSSI와 동일하고 축 그리드에 정렬됨.
        for rp, sp in zip(retry_pts, rssi_pts):
            assert rp["bin"] == sp["bin"]
            assert rp["epoch"] == axis["bins"][rp["bin"]]
            assert bin_index_for(axis, rp["epoch"]) == rp["bin"]

    def test_retry_and_rssi_share_bin_for_same_epoch_in_one_bin(self):
        # 한 bin 안의 retry/RSSI 샘플은 같은 단일 bin(0)으로 집계된다.
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_size_sec=10.0)
        assert axis["bin_count"] == 1
        rssi_pts = project_rssi_series([_rssi(1002.0, -60), _rssi(1004.0, -62)], axis)
        retry_pts = project_retry_series([_frame(1002.0, True), _frame(1004.0, False)], axis)
        assert len(rssi_pts) == len(retry_pts) == 1
        assert retry_pts[0]["bin"] == rssi_pts[0]["bin"] == 0
        assert retry_pts[0]["epoch"] == rssi_pts[0]["epoch"]

    def test_points_are_time_ordered(self):
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_count=10)
        shuffled = [_frame(1009.0, True), _frame(1001.0, False), _frame(1005.0, True)]
        points = project_retry_series(shuffled, axis)
        bins = [p["bin"] for p in points]
        epochs = [p["epoch"] for p in points]
        assert bins == sorted(bins)
        assert epochs == sorted(epochs)

    def test_bool_flags_counted_per_bin(self):
        # 한 bin 안 3프레임 중 2개 retry → retry=2, total=3, retry_pct=66.7.
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_size_sec=10.0)
        assert axis["bin_count"] == 1
        points = project_retry_series(
            [_frame(1000.0, True), _frame(1002.0, False), _frame(1004.0, True)], axis
        )
        assert len(points) == 1
        p = points[0]
        assert p["bin"] == 0
        assert p["retry"] == 2
        assert p["total"] == 3
        assert p["count"] == 3
        assert p["retry_pct"] == 66.7

    def test_int_counts_supported(self):
        # retry가 카운트(int)로 들어오면 합산된다("counts/flags").
        axis = build_time_axis([[_frame(1000.0, 0), _frame(1010.0, 0)]], bin_size_sec=10.0)
        points = project_retry_series(
            [_frame(1000.0, 3), _frame(1002.0, 2)], axis
        )
        assert len(points) == 1
        assert points[0]["retry"] == 5
        assert points[0]["total"] == 2

    def test_distinct_bins_yield_distinct_points(self):
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_size_sec=1.0)
        points = project_retry_series(
            [_frame(1000.0, True), _frame(1005.0, False), _frame(1009.0, True)], axis
        )
        assert [p["bin"] for p in points] == [0, 5, 9]
        assert [p["retry"] for p in points] == [1, 0, 1]

    def test_skips_frames_missing_epoch_but_keeps_missing_retry(self):
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_size_sec=10.0)
        dirty = [
            {"retry": True},              # epoch 없음 → skip
            {"epoch": None, "retry": True},  # epoch None → skip
            {"epoch": 1000.0},            # retry 없음 → 비-retry 프레임(total 집계)
            _frame(1002.0, True),         # 유효 retry
        ]
        points = project_retry_series(dirty, axis)
        assert len(points) == 1
        assert points[0]["total"] == 2   # 두 유효 프레임
        assert points[0]["retry"] == 1   # 그 중 retry 1건

    def test_out_of_range_frames_clamped_to_end_bins(self):
        axis = build_time_axis([[_frame(1000.0, True), _frame(1010.0, False)]], bin_count=10)
        points = project_retry_series(
            [_frame(990.0, True), _frame(9999.0, True)], axis
        )
        bins = {p["bin"] for p in points}
        assert bins == {0, axis["bin_count"] - 1}

    def test_large_capture_is_downsampled_to_bin_count(self):
        axis = build_time_axis([[_frame(0.0, True), _frame(100.0, False)]], bin_count=50)
        many = [_frame(i * 0.01, i % 2 == 0) for i in range(10000)]
        points = project_retry_series(many, axis)
        assert len(points) <= axis["bin_count"]
        assert [p["bin"] for p in points] == sorted(p["bin"] for p in points)


class TestProjectPingSeriesAlignment:
    def test_empty_axis_returns_empty(self):
        axis = build_time_axis([])  # empty=True, bin_count=0
        assert project_ping_series([_success(1000.0)], axis) == []

    def test_empty_events_returns_empty(self):
        axis = build_time_axis([[_success(1000.0), _loss(1010.0)]], bin_count=10)
        assert project_ping_series([], axis) == []

    def test_success_and_loss_land_at_correct_time_positions(self):
        # 핵심 AC: 성공·손실 이벤트가 공유 축 위 '정확한 시간 위치'(bin)에 떨어지는지.
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_size_sec=1.0
        )  # 10 bins, bin_size=1.0
        # 성공 @1000→bin0, 손실 @1005→bin5, 성공 @1009→bin9.
        points = project_ping_series(
            [_success(1000.0), _loss(1005.0), _success(1009.0)], axis
        )
        # epoch → 기대 bin 인덱스 (bin_index_for와 동일 매핑).
        assert bin_index_for(axis, 1000.0) == 0
        assert bin_index_for(axis, 1005.0) == 5
        assert bin_index_for(axis, 1009.0) == 9
        assert [p["bin"] for p in points] == [0, 5, 9]
        # 각 포인트 epoch은 정확히 그 bin의 왼쪽 경계(축 그리드에 정렬).
        for p in points:
            assert p["epoch"] == axis["bins"][p["bin"]]
            assert bin_index_for(axis, p["epoch"]) == p["bin"]
        # 성공은 success 카운트에, 손실은 loss 카운트에 정확히 분류.
        by_bin = {p["bin"]: p for p in points}
        assert by_bin[0]["success"] == 1 and by_bin[0]["loss"] == 0
        assert by_bin[5]["success"] == 0 and by_bin[5]["loss"] == 1
        assert by_bin[9]["success"] == 1 and by_bin[9]["loss"] == 0

    def test_ping_bins_align_to_rssi_and_retry_series_bins(self):
        # ping outcome이 RSSI/retry 시계열과 '같은 축 bin'에 정렬되는지 검증.
        epochs = [1000.0, 1003.0, 1006.0, 1009.0]
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_count=10
        )
        rssi_pts = project_rssi_series([_rssi(e, -60) for e in epochs], axis)
        retry_pts = project_retry_series([_frame(e, True) for e in epochs], axis)
        ping_pts = project_ping_series([_success(e) for e in epochs], axis)

        # 같은 axis·같은 epoch → 동일한 bin 인덱스 시퀀스.
        assert [p["bin"] for p in ping_pts] == [p["bin"] for p in rssi_pts]
        assert [p["bin"] for p in ping_pts] == [p["bin"] for p in retry_pts]
        # 같은 bin-경계 epoch (축 그리드에 동일 정렬).
        assert [p["epoch"] for p in ping_pts] == [p["epoch"] for p in rssi_pts]
        for pp, sp in zip(ping_pts, rssi_pts):
            assert pp["bin"] == sp["bin"]
            assert pp["epoch"] == axis["bins"][pp["bin"]]
            assert bin_index_for(axis, pp["epoch"]) == pp["bin"]

    def test_success_and_loss_in_same_bin_are_bucketed(self):
        # 한 bin 안 성공 2 + 손실 1 → success=2, loss=1, total=3, loss_pct=33.3.
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_size_sec=10.0
        )  # 1 bin
        assert axis["bin_count"] == 1
        points = project_ping_series(
            [_success(1000.0), _success(1002.0), _loss(1004.0)], axis
        )
        assert len(points) == 1
        p = points[0]
        assert p["bin"] == 0
        assert p["success"] == 2
        assert p["loss"] == 1
        assert p["total"] == 3
        assert p["count"] == 3
        assert p["loss_pct"] == 33.3

    def test_loss_gap_status_counts_as_loss(self):
        # seq-gap 추정 손실("loss_gap")도 손실로 집계된다.
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_size_sec=10.0
        )
        points = project_ping_series(
            [_loss(1000.0, status="loss"), _loss(1002.0, status="loss_gap")], axis
        )
        assert len(points) == 1
        assert points[0]["loss"] == 2
        assert points[0]["success"] == 0
        assert points[0]["loss_pct"] == 100.0

    def test_points_are_time_ordered(self):
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_count=10
        )
        shuffled = [_loss(1009.0), _success(1001.0), _success(1005.0)]
        points = project_ping_series(shuffled, axis)
        bins = [p["bin"] for p in points]
        epochs = [p["epoch"] for p in points]
        assert bins == sorted(bins)
        assert epochs == sorted(epochs)

    def test_distinct_bins_yield_distinct_points(self):
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_size_sec=1.0
        )
        points = project_ping_series(
            [_success(1000.0), _loss(1005.0), _success(1009.0)], axis
        )
        assert [p["bin"] for p in points] == [0, 5, 9]
        assert [(p["success"], p["loss"]) for p in points] == [(1, 0), (0, 1), (1, 0)]

    def test_skips_missing_none_bool_epoch_and_unclassified_status(self):
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_size_sec=10.0
        )
        dirty = [
            {"status": "matched"},                  # epoch 없음 → skip
            {"epoch": None, "status": "matched"},      # epoch None → skip
            {"epoch": True, "status": "loss"},         # epoch bool → skip
            {"epoch": 1001.0, "status": "observed"},   # 성공·손실 아님 → skip
            {"epoch": 1002.0, "status": None},         # status None → skip
            _success(1003.0),                       # 유효 성공
            _loss(1004.0),                          # 유효 손실
        ]
        points = project_ping_series(dirty, axis)
        assert len(points) == 1
        assert points[0]["success"] == 1
        assert points[0]["loss"] == 1
        assert points[0]["count"] == 2

    def test_out_of_range_events_clamped_to_end_bins(self):
        axis = build_time_axis(
            [[_success(1000.0), _loss(1010.0)]], bin_count=10
        )
        points = project_ping_series(
            [_success(990.0), _loss(9999.0)], axis
        )
        bins = {p["bin"] for p in points}
        assert bins == {0, axis["bin_count"] - 1}

    def test_large_capture_is_downsampled_to_bin_count(self):
        axis = build_time_axis(
            [[_success(0.0), _loss(100.0)]], bin_count=50
        )
        many = [
            _success(i * 0.01) if i % 2 == 0 else _loss(i * 0.01)
            for i in range(10000)
        ]
        points = project_ping_series(many, axis)
        assert len(points) <= axis["bin_count"]
        assert [p["bin"] for p in points] == sorted(p["bin"] for p in points)
