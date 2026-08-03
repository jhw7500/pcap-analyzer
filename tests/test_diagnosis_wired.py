"""유선 확정 손실 구간 ↔ 무선 이벤트 대조 이슈."""
from analyzer.web.structured import _ground_truth_issue_candidates
from tests.conftest import make_frame, AP1, STA1, STA2

#: gt['sender'] — STA1 자신이 ping 발신자인 배치를 가정(_sender_sta_macs 매핑용).
SENDER_IP = "10.0.0.9"
#: GT가 집계하는 ping 대상 IP.
TARGET_IP = "10.0.0.2"
#: conftest에 없는 제3의 STA — 무관 트래픽 오염 시나리오용.
STA3 = "aa:bb:cc:00:00:04"

#: structured["signal"]["stas"] — cliff의 STA 이름을 MAC으로 되돌리는 매핑.
SIGNAL_STAS = {"STA1(0002)": {"mac": STA1}, "STA2(0003)": {"mac": STA2}}

GT = {"sender": SENDER_IP,
      "streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                   "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}


def _ping_anchor(**kw):
    """GT ping 모집단에 속하는 echo request 프레임 — STA 매핑 앵커.

    매핑 앵커는 sender IP가 실린 아무 패킷이 아니라 GT가 집계한 ping이어야 한다
    (PR #22 7라운드) — 그래서 픽스처도 icmp_type/ip_dst를 갖춘 실제 echo request다.
    """
    base = dict(subtype="40", ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8")
    base.update(kw)
    return make_frame(**base)

#: sender 필드는 있으나 프레임에 매칭되는 IP가 전혀 없는(매핑 실패) 시나리오용 —
#: 프레임 자체는 GT와 동일하게 구성하되 ip_src/ip_dst를 비워 둔다.
GT_NO_MATCH = {"sender": "10.0.0.99",
               "streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                            "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}


def test_candidate_with_roaming_evidence_stays_high_despite_single_retry():
    """로밍은 그 자체로 high 트리거 — 창 안 낱개 retry(폭주 미달)는 근거 refs엔 남되
    '재전송 폭주' 문구는 붙지 않는다(폭주 기준 미달)."""
    frames = [
        make_frame(number=1, epoch=1004.0, subtype="11"),  # Auth — 창(±2s) 안
        # 이 ping 프레임이 STA1(기본 ta)을 sta_macs로 매핑하는 앵커를 겸한다.
        _ping_anchor(number=2, epoch=1005.5, retry=True),  # 재전송 1건 — 폭주 미달
        make_frame(number=3, epoch=1030.0, subtype="40"),  # 창 밖
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
        _ping_anchor(number=1, epoch=1005.0, retry=True),
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
        _ping_anchor(number=1, epoch=1005.0, retry=True),
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
                          ip_src=SENDER_IP if i == 1 else "",
                          ip_dst=TARGET_IP if i == 1 else "",
                          icmp_type="8" if i == 1 else "") for i in range(1, 12)]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]


def test_signal_cliff_overlap_alone_triggers_high():
    """매핑된 sender STA의 cliff만 창과 겹쳐도 high — refs는 evidence.cliff_evidence가
    소싱한 cliff 근처(±1초) 프레임이다. 창 안이지만 cliff와 떨어진 프레임은 근거가
    아니다(PR #22 4라운드 — '창 안 아무 프레임' 폴백은 인과성이 없다)."""
    frames = [
        _ping_anchor(number=5, epoch=1005.2),              # cliff 근처
        make_frame(number=6, epoch=1007.5, subtype="40"),  # 창 안이지만 cliff에서 2.5초 밖
    ]
    signal_cliffs = {
        "STA1(0002)": {
            "cliffs": [{"epoch": 1005.0, "duration_sec": 1.0, "drop_db": 12,
                        "rssi_before": -50, "rssi_after": -62}],
            "moving_avg": [],
        },
    }
    cands = _ground_truth_issue_candidates(GT, frames, signal_cliffs, SIGNAL_STAS)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "RSSI 절벽 1건" in c["issue"]["msg"]
    assert c["refs"] == [5]


def test_signal_cliff_outside_window_not_counted():
    """cliff 시간 구간이 손실 창과 안 겹치면 무시된다."""
    frames = [_ping_anchor(number=5, epoch=1005.2)]
    signal_cliffs = {
        "STA1(0002)": {
            "cliffs": [{"epoch": 1500.0, "duration_sec": 1.0, "drop_db": 20}],
            "moving_avg": [],
        },
    }
    cands = _ground_truth_issue_candidates(GT, frames, signal_cliffs, SIGNAL_STAS)
    assert len(cands) == 1
    assert cands[0]["issue"]["severity"] == "medium"
    assert "RSSI" not in cands[0]["issue"]["msg"]


def test_unrelated_sta_cliff_does_not_trigger_anomaly():
    """무관한 STA2의 RSSI 절벽이 손실 창과 겹쳐도, 매핑된 대상 STA1의 유선 손실을
    이상 징후로 둔갑시키면 안 된다(PR #22 4라운드 — cliff도 로밍/retry와 같은
    STA 스코프를 받는다)."""
    frames = [
        _ping_anchor(number=1, epoch=1005.2),                       # STA1 정상
        make_frame(number=2, epoch=1005.1, subtype="40", ta=STA2),  # STA2 트래픽
    ]
    signal_cliffs = {
        "STA2(0003)": {
            "cliffs": [{"epoch": 1005.0, "duration_sec": 1.0, "drop_db": 20}],
            "moving_avg": [],
        },
    }
    cands = _ground_truth_issue_candidates(GT, frames, signal_cliffs, SIGNAL_STAS)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1]  # STA2 프레임은 스코프 밖


def test_mapping_failure_keeps_all_sta_cliffs():
    """STA 매핑이 실패하면 어느 STA의 cliff인지 가릴 근거가 없으므로 기존대로
    전체 cliff를 보되, 귀속이 불확실하므로 medium으로 낮춘다."""
    frames = [make_frame(number=1, epoch=1005.1, subtype="40", ta=STA2)]
    signal_cliffs = {
        "STA2(0003)": {
            "cliffs": [{"epoch": 1005.0, "duration_sec": 1.0, "drop_db": 20}],
            "moving_avg": [],
        },
    }
    cands = _ground_truth_issue_candidates(GT_NO_MATCH, frames, signal_cliffs, SIGNAL_STAS)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "RSSI 절벽 1건" in c["issue"]["msg"]
    assert "매핑 불가" in c["issue"]["msg"]
    assert c["refs"] == [1]  # cliff_evidence(STA2)가 소싱한 근처 프레임


def test_malformed_signal_cliffs_do_not_crash():
    """구버전 직렬화 result에서 signal_cliffs가 null/비-dict여도 죽지 않는다."""
    frames = [_ping_anchor(number=5, epoch=1005.2)]
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
        _ping_anchor(number=1, epoch=1005.2),
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
        make_frame(number=1, epoch=1005.0, subtype="11"),           # STA1(기본 ta) 로밍
        make_frame(number=2, epoch=1005.1, subtype="40", ta=STA2),  # 무관 STA2 정상 트래픽
        _ping_anchor(number=3, epoch=1005.2),                       # STA1 매핑 앵커
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


def test_upstream_sender_scopes_to_sta_not_ap():
    """상류 토폴로지(유선 EXPING PC가 AP 너머의 STA를 ping)에서 sender IP가 걸린
    프레임의 무선 상대는 AP다 — 다운링크 요청은 ta=AP, 업링크 응답은 ra=AP.
    AP를 STA로 매핑하면 그 AP를 경유하는 **모든** 무선 트래픽이 스코프에 들어와
    스코프가 무력화된다(무관 STA2의 로밍/재전송 폭주가 다시 high로 둔갑).
    detected roles의 AP를 배제해 반대편 비-AP MAC을 골라야 한다 (PR #22 6라운드)."""
    frames = [
        # 다운링크 요청: AP가 sender의 echo request를 STA1로 내려보낸다(ta=AP)
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=STA1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
        # 업링크 응답: STA1이 sender로 돌려보낸다(ra=AP)
        make_frame(number=2, epoch=1005.05, subtype="40", ta=STA1, ra=AP1,
                   ip_src=TARGET_IP, ip_dst=SENDER_IP, icmp_type="0"),
        # 무관한 STA2의 로밍 + 재전송 폭주 — 전부 같은 AP를 경유한다
        make_frame(number=3, epoch=1005.1, subtype="11", ta=STA2, ra=AP1),
        make_frame(number=4, epoch=1005.2, subtype="40", retry=True, ta=STA2, ra=AP1),
        make_frame(number=5, epoch=1005.3, subtype="40", retry=True, ta=STA2, ra=AP1),
        make_frame(number=6, epoch=1005.4, subtype="40", retry=True, ta=STA2, ra=AP1),
    ]
    cands = _ground_truth_issue_candidates(GT, frames, ap_macs={AP1})
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1, 2]           # STA2 프레임은 스코프 밖
    assert STA1 in c["issue"]["msg"] and AP1 not in c["issue"]["msg"]


def test_upstream_sender_own_sta_roaming_stays_high():
    """상류 토폴로지에서도 대상 STA 자신의 로밍은 high로 잡힌다(과소 차단 방지)."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=STA1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
        make_frame(number=2, epoch=1005.1, subtype="11", ta=STA1, ra=AP1),  # STA1 로밍
        make_frame(number=3, epoch=1005.2, subtype="40", ta=STA2, ra=AP1),  # 무관 STA2
    ]
    cands = _ground_truth_issue_candidates(GT, frames, ap_macs={AP1})
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert c["refs"] == [2]  # 이상 징후가 있으면 refs는 그 근거(로밍) 프레임뿐


def test_sta_sender_topology_unchanged_by_ap_macs():
    """sender가 STA 자신인 기존 토폴로지는 ap_macs를 줘도 결과가 같고, 인자를
    생략한 기본 경로(구 호출부)도 동일하다 — 하위 호환."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="11"),           # STA1 로밍
        make_frame(number=2, epoch=1005.1, subtype="40", ta=STA2),  # 무관 STA2
        _ping_anchor(number=3, epoch=1005.2),                       # STA1 매핑 앵커
    ]
    without_ap = _ground_truth_issue_candidates(GT, frames)
    with_ap = _ground_truth_issue_candidates(GT, frames, ap_macs={AP1})
    assert without_ap == with_ap
    assert with_ap[0]["issue"]["severity"] == "high"
    assert with_ap[0]["refs"] == [1]


#: targets가 실린 GT — 매핑 앵커를 그 대상들과의 ping으로만 한정하는지 검증용.
GT_WITH_TARGETS = {
    "sender": SENDER_IP,
    "targets": {TARGET_IP: {"total": 10, "ng": 3}},
    "streaks": [{"target": TARGET_IP, "start_epoch": 1005.0,
                 "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}],
}


def test_non_icmp_traffic_from_sender_is_not_a_mapping_anchor():
    """상류 sender가 대상 STA1로 ping하면서 무관한 STA3으로 TCP도 보내면, 그 TCP
    프레임이 앵커가 되어 STA3까지 sta_macs에 섞인다 — 그러면 STA3의 로밍이 대상
    STA1의 유선 손실을 high로 둔갑시킨다. 앵커는 GT가 집계한 ping 모집단
    (ICMP echo)만이어야 한다 (PR #22 7라운드)."""
    frames = [
        # 대상 STA1과의 ping — 유일한 정당한 앵커
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=STA1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
        make_frame(number=2, epoch=1005.05, subtype="40", ta=STA1, ra=AP1,
                   ip_src=TARGET_IP, ip_dst=SENDER_IP, icmp_type="0"),
        # 같은 sender가 무관한 STA3으로 보내는 TCP — ICMP가 아니다
        make_frame(number=3, epoch=1005.1, subtype="40", ta=AP1, ra=STA3,
                   ip_src=SENDER_IP, ip_dst="10.0.0.7", tcp_len="512"),
        make_frame(number=4, epoch=1005.2, subtype="11", ta=STA3, ra=AP1),  # STA3 로밍
    ]
    cands = _ground_truth_issue_candidates(GT_WITH_TARGETS, frames, ap_macs={AP1})
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1, 2]           # STA3 프레임은 스코프 밖
    assert STA3 not in c["issue"]["msg"]


def test_icmp_to_non_gt_target_is_not_a_mapping_anchor():
    """같은 sender가 GT 집계 대상이 아닌 IP로 보낸 ping도 앵커가 아니다 —
    GT의 targets에 있는 흐름만 그 GT의 모집단이다."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=STA1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
        # GT targets 밖(10.0.0.7)의 STA3으로 보낸 ping
        make_frame(number=2, epoch=1005.1, subtype="40", ta=AP1, ra=STA3,
                   ip_src=SENDER_IP, ip_dst="10.0.0.7", icmp_type="8"),
        make_frame(number=3, epoch=1005.2, subtype="11", ta=STA3, ra=AP1),  # STA3 로밍
    ]
    cands = _ground_truth_issue_candidates(GT_WITH_TARGETS, frames, ap_macs={AP1})
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1]


def test_missing_targets_falls_back_to_sender_icmp_only():
    """targets가 없는 GT(구버전 결과 등)는 sender 기준 ICMP echo만으로 매핑한다 —
    대상 목록이 없다는 이유로 매핑을 포기하지 않는다."""
    gt_no_targets = dict(GT_WITH_TARGETS)
    gt_no_targets.pop("targets")
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=STA1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
        make_frame(number=2, epoch=1005.1, subtype="11", ta=STA1, ra=AP1),  # STA1 로밍
        make_frame(number=3, epoch=1005.2, subtype="40", ta=STA2, ra=AP1),  # 무관 STA2
    ]
    cands = _ground_truth_issue_candidates(gt_no_targets, frames, ap_macs={AP1})
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert c["refs"] == [2]


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
