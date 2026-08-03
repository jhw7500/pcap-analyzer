"""유선 확정 손실 구간 ↔ 무선 이벤트 대조 이슈."""
from analyzer.web.structured import _ground_truth_issue_candidates
from tests.conftest import make_frame, STA2

#: gt['sender'] — STA1 자신이 ping 발신자인 배치를 가정(_sender_sta_macs 매핑용).
SENDER_IP = "10.0.0.9"

GT = {"sender": SENDER_IP,
      "streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                   "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}

#: sender 필드는 있으나 프레임에 매칭되는 IP가 전혀 없는(매핑 실패) 시나리오용 —
#: 프레임 자체는 GT와 동일하게 구성하되 ip_src/ip_dst를 비워 둔다.
GT_NO_MATCH = {"sender": "10.0.0.99",
               "streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                            "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}


def test_candidate_with_roaming_evidence_stays_high_despite_single_retry():
    """로밍은 그 자체로 high 트리거 — 창 안 낱개 retry(폭주 미달)는 근거 refs엔 남되
    '재전송 폭주' 문구는 붙지 않는다(폭주 기준 미달)."""
    frames = [
        # ip_src=SENDER_IP가 STA1(기본 ta)을 sta_macs로 매핑하는 앵커 역할도 겸한다.
        make_frame(number=1, epoch=1004.0, subtype="11", ip_src=SENDER_IP),  # Auth — 창(±2s) 안
        make_frame(number=2, epoch=1005.5, subtype="40", retry=True),  # 재전송 1건 — 폭주 미달
        make_frame(number=3, epoch=1030.0, subtype="40"),              # 창 밖
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["refs"] == [1, 2]
    assert c["window"] == {"start_epoch": 1003.0, "end_epoch": 1008.0}
    assert c["signal_type"] == "wired_loss"
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert "재전송 폭주" not in c["issue"]["msg"]
    assert "매핑 불가" not in c["issue"]["msg"]


def test_single_retry_without_burst_is_not_anomaly():
    """창 안 데이터 프레임 1건만 retry(폭주 기준 미달, 로밍·cliff 없음) → medium."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", retry=True, ip_src=SENDER_IP),
        make_frame(number=2, epoch=1005.2, subtype="40"),
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1, 2]


def test_retry_burst_triggers_high():
    """창 안 데이터 프레임 중 retry 3건/5건(60%) → 폭주 기준(3건·30%) 충족 → high."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", retry=True, ip_src=SENDER_IP),
        make_frame(number=2, epoch=1005.1, subtype="40", retry=True),
        make_frame(number=3, epoch=1005.2, subtype="40", retry=True),
        make_frame(number=4, epoch=1005.3, subtype="40"),
        make_frame(number=5, epoch=1005.4, subtype="40"),
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "재전송 폭주(3/5=60%)" in c["issue"]["msg"]
    assert c["refs"] == [1, 2, 3]


def test_retry_below_pct_threshold_is_not_burst():
    """건수(3건)는 충족해도 비율이 30% 미만이면 폭주가 아니다 (3/11=27%)."""
    frames = [make_frame(number=i, epoch=1005.0 + i * 0.01, subtype="40",
                          retry=(i <= 3),
                          ip_src=SENDER_IP if i == 1 else "") for i in range(1, 12)]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]


def test_signal_cliff_overlap_alone_triggers_high():
    """로밍·재전송 폭주 없이 signal_cliff만 창과 겹쳐도 high — refs는 스코프 프레임 폴백."""
    frames = [make_frame(number=5, epoch=1005.2, subtype="40", ip_src=SENDER_IP)]  # 정상 트래픽
    signal_cliffs = {
        "STA1(0002)": {
            "cliffs": [{"epoch": 1005.0, "duration_sec": 1.0, "drop_db": 12,
                        "rssi_before": -50, "rssi_after": -62}],
            "moving_avg": [],
        },
    }
    cands = _ground_truth_issue_candidates(GT, frames, signal_cliffs)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "RSSI 절벽 1건" in c["issue"]["msg"]
    assert c["refs"] == [5]  # 로밍/retry 프레임이 없어 스코프 전체(=STA1)로 폴백


def test_signal_cliff_outside_window_not_counted():
    """cliff 시간 구간이 손실 창과 안 겹치면 무시된다."""
    frames = [make_frame(number=5, epoch=1005.2, subtype="40", ip_src=SENDER_IP)]
    signal_cliffs = {
        "STA1(0002)": {
            "cliffs": [{"epoch": 1500.0, "duration_sec": 1.0, "drop_db": 20}],
            "moving_avg": [],
        },
    }
    cands = _ground_truth_issue_candidates(GT, frames, signal_cliffs)
    assert len(cands) == 1
    assert cands[0]["issue"]["severity"] == "medium"
    assert "RSSI" not in cands[0]["issue"]["msg"]


def test_malformed_signal_cliffs_do_not_crash():
    """구버전 직렬화 result에서 signal_cliffs가 null/비-dict여도 죽지 않는다."""
    frames = [make_frame(number=5, epoch=1005.2, subtype="40", ip_src=SENDER_IP)]
    assert _ground_truth_issue_candidates(GT, frames, None)[0]["issue"]["severity"] == "medium"
    assert _ground_truth_issue_candidates(GT, frames, "not-a-dict")[0]["issue"]["severity"] == "medium"


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


# --------------------------------------------------------------------------
# STA 스코프 대조 (PR #22 2라운드 리뷰 — 다중 STA 캡처에서 무관한 STA의
# 로밍/재전송이 다른 STA의 유선 손실을 이상 징후로 둔갑시키지 않도록)
# --------------------------------------------------------------------------


def test_unrelated_sta_roaming_and_retry_do_not_count():
    """무관한 STA2의 로밍/재전송(폭주 수준)이 창 안에 있어도, 매핑된 대상 STA1
    기준으로는 '이상 징후 없음'(medium)이어야 한다."""
    frames = [
        # 매핑 앵커 + 대상 STA1의 정상 트래픽(스코프 안, 이상 없음)
        make_frame(number=1, epoch=1005.2, subtype="40", ip_src=SENDER_IP),
        # 무관한 STA2의 로밍 + 재전송 폭주 — 전부 창(±2s) 안
        make_frame(number=2, epoch=1005.0, subtype="11", ta=STA2),
        make_frame(number=3, epoch=1005.1, subtype="40", retry=True, ta=STA2),
        make_frame(number=4, epoch=1005.2, subtype="40", retry=True, ta=STA2),
        make_frame(number=5, epoch=1005.3, subtype="40", retry=True, ta=STA2),
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1]  # STA2 프레임은 스코프 밖


def test_target_sta_own_roaming_stays_high():
    """대상 STA 자신의 로밍은 매핑 성공 시에도 여전히 high다."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="11", ip_src=SENDER_IP),  # STA1(기본 ta) 로밍
        make_frame(number=2, epoch=1005.1, subtype="40", ta=STA2),           # 무관 STA2 정상 트래픽
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert "매핑 불가" not in c["issue"]["msg"]
    assert c["refs"] == [1]


def test_ip_mapping_failure_falls_back_to_network_wide_medium():
    """ip_src/ip_dst가 전부 비어 STA 매핑이 실패하면(암호화 미해제 캡처 등) 전체
    무선 기준으로 폴백하되, 귀속이 불확실하므로 severity는 high가 아니라
    medium으로 낮추고 msg에 매핑 실패를 명시한다."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="11"),  # 로밍 — IP 정보 없음
    ]
    cands = _ground_truth_issue_candidates(GT_NO_MATCH, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert "매핑 불가" in c["issue"]["msg"] and "전체 무선 기준" in c["issue"]["msg"]
    assert c["refs"] == [1]


def test_missing_sender_key_treated_as_mapping_failure():
    """gt에 sender 키 자체가 없으면(구버전 캐시 등) 빈 문자열로 취급해 매핑
    실패로 처리한다 — 프레임의 기본 ip_src=""와 우연히 매칭되면 안 된다."""
    gt_no_sender = {"streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                                  "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}
    frames = [make_frame(number=1, epoch=1005.0, subtype="11")]  # ip_src="" 기본값
    cands = _ground_truth_issue_candidates(gt_no_sender, frames)
    assert len(cands) == 1
    assert cands[0]["issue"]["severity"] == "medium"
    assert "매핑 불가" in cands[0]["issue"]["msg"]
