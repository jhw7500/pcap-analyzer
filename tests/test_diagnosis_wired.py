"""유선 확정 손실 구간 ↔ 무선 이벤트 대조 이슈."""
import pytest

from analyzer.web.structured import (
    _ground_truth_issue_candidates,
    _sender_sta_macs_by_target,
)
from tests.conftest import make_frame, AP1, STA1, STA2

#: gt['sender'] — STA1 자신이 ping 발신자인 배치를 가정(STA 매핑용).
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


# --------------------------------------------------------------------------
# 매핑·귀속 축 전수 스윕 (PR #22 8라운드 — 토폴로지 × 시나리오를 한 곳에서 고정)
#
# 여기서 함께 검증하는 축:
#   - streak별 target STA 귀속(8라운드): 다른 target STA의 이벤트가 이 streak로 새지 않는다
#   - AP 배제(6라운드) / 비-ICMP·GT 밖 target 앵커 배제(7라운드) / 브로드캐스트 배제
#   - target별 매핑 일부 실패 → 그 streak만 매핑 실패 폴백
#   - cliff 스코프(4라운드)도 streak별 sta_macs를 따른다
# --------------------------------------------------------------------------

BROADCAST = "ff:ff:ff:ff:ff:ff"
TARGET_A, TARGET_B, TARGET_C = "10.0.0.2", "10.0.0.3", "10.0.0.4"
#: 무선 프레임이 하나도 없는 target(C) 포함 — 그 streak만 매핑 실패로 떨어져야 한다.
GT_SWEEP = {
    "sender": SENDER_IP,
    "targets": {TARGET_A: {"total": 9, "ng": 3}, TARGET_B: {"total": 9, "ng": 2},
                TARGET_C: {"total": 9, "ng": 1}},
    "streaks": [
        {"target": TARGET_A, "start_epoch": 1005.0, "end_epoch": 1006.0,
         "count": 3, "duration_sec": 1.0},
        {"target": TARGET_B, "start_epoch": 1105.0, "end_epoch": 1106.0,
         "count": 2, "duration_sec": 1.0},
        {"target": TARGET_C, "start_epoch": 1205.0, "end_epoch": 1206.0,
         "count": 1, "duration_sec": 1.0},
    ],
}
#: STA2의 RSSI 절벽이 target A의 손실 창과 겹친다 — A로 새면 안 된다.
SWEEP_CLIFFS = {"STA2(0003)": {"cliffs": [{"epoch": 1005.1, "duration_sec": 0.5,
                                           "drop_db": 20}], "moving_avg": []}}


def _sweep_ping(topology, number, epoch, target, sta, icmp_type):
    """토폴로지별 ping 프레임 한 장.

    direct = sender가 STA 자신(업링크 요청 ta=STA, 다운링크 응답 ra=STA),
    upstream = sender가 AP 상류의 유선 호스트(다운링크 요청 ta=AP·ra=STA,
    업링크 응답 ta=STA·ra=AP).
    """
    if icmp_type == "8":  # echo request: sender → target
        ta, ra = (sta, AP1) if topology == "direct" else (AP1, sta)
        ip_src, ip_dst = SENDER_IP, target
    else:                 # echo reply: target → sender
        ta, ra = (AP1, sta) if topology == "direct" else (sta, AP1)
        ip_src, ip_dst = target, SENDER_IP
    return make_frame(number=number, epoch=epoch, subtype="40", ta=ta, ra=ra,
                      ip_src=ip_src, ip_dst=ip_dst, icmp_type=icmp_type)


def _sweep_frames(topology):
    """오염원이 골고루 섞인 캡처.

    direct 토폴로지에서는 sender의 모든 target ping이 같은 무선 MAC(STA1)에서
    나가므로 target A/B 모두 STA1로 매핑된다 — 같은 라디오이므로 정상이다.
    upstream에서는 target마다 다른 STA(A→STA1, B→STA2)로 갈린다.
    """
    sta_a = STA1
    sta_b = STA1 if topology == "direct" else STA2
    # 비-ICMP 오염: 두 토폴로지 모두 "sender IP가 실린 프레임의 상대가 STA3"이 되는
    # 배치 — ICMP 조건이 없으면 STA3이 매핑에 섞인다.
    if topology == "direct":
        tcp = make_frame(number=9, epoch=1005.7, subtype="40", ta=STA3, ra=AP1,
                         ip_src="10.0.0.7", ip_dst=SENDER_IP, tcp_len="512")
        # 브로드캐스트 오염: 상대가 브로드캐스트로 계산되는 echo reply
        bcast = make_frame(number=10, epoch=1005.8, subtype="40", ta=AP1, ra=BROADCAST,
                           ip_src=TARGET_A, ip_dst=SENDER_IP, icmp_type="0")
    else:
        tcp = make_frame(number=9, epoch=1005.7, subtype="40", ta=AP1, ra=STA3,
                         ip_src=SENDER_IP, ip_dst="10.0.0.7", tcp_len="512")
        bcast = make_frame(number=10, epoch=1005.8, subtype="40", ta=AP1, ra=BROADCAST,
                           ip_src=SENDER_IP, ip_dst=TARGET_A, icmp_type="8")
    return [
        # ── target A 손실 창(1003~1008) ──
        _sweep_ping(topology, 1, 1005.0, TARGET_A, sta_a, "8"),
        _sweep_ping(topology, 2, 1005.05, TARGET_A, sta_a, "0"),
        make_frame(number=3, epoch=1005.5, subtype="40", ta=sta_a, ra=AP1),  # 대상 STA 정상
        make_frame(number=4, epoch=1005.2, subtype="11", ta=STA2, ra=AP1),   # 다른 target STA 로밍
        make_frame(number=5, epoch=1005.30, subtype="40", ta=STA2, ra=AP1, retry=True),
        make_frame(number=6, epoch=1005.32, subtype="40", ta=STA2, ra=AP1, retry=True),
        make_frame(number=7, epoch=1005.34, subtype="40", ta=STA2, ra=AP1, retry=True),
        make_frame(number=8, epoch=1005.6, subtype="11", ta=STA3, ra=AP1),   # 무관 STA 로밍
        tcp,
        bcast,
        # ── target B 손실 창(1103~1108) ──
        _sweep_ping(topology, 11, 1105.0, TARGET_B, sta_b, "8"),
        _sweep_ping(topology, 12, 1105.05, TARGET_B, sta_b, "0"),
        make_frame(number=13, epoch=1105.3, subtype="11", ta=STA2, ra=AP1),  # STA2 로밍
        make_frame(number=14, epoch=1105.4, subtype="40", ta=STA1, ra=AP1),  # STA1 정상
        # ── target C 손실 창(1203~1208) — C의 ping은 무선에 하나도 안 잡혔다 ──
        make_frame(number=15, epoch=1205.0, subtype="40", ta=STA3, ra=AP1),
    ]


@pytest.mark.parametrize("topology,target,severity,fragment,refs", [
    # direct: A/B 모두 sender 자신의 라디오(STA1)로 매핑 — STA2/STA3 이벤트는 전부 밖.
    ("direct", TARGET_A, "medium", "이상 징후 없음", [1, 2, 3]),
    ("direct", TARGET_B, "medium", "이상 징후 없음", [11, 12, 14]),
    ("direct", TARGET_C, "medium", "매핑 불가", [15]),
    # upstream: A→STA1, B→STA2. A의 창에 있는 STA2의 로밍·재전송 폭주·RSSI 절벽은
    # B의 STA 것이므로 A를 high로 만들면 안 되고, B는 자기 STA의 로밍으로 high다.
    ("upstream", TARGET_A, "medium", "이상 징후 없음", [1, 2, 3]),
    ("upstream", TARGET_B, "high", "로밍/해제 1건", [13]),
    ("upstream", TARGET_C, "medium", "매핑 불가", [15]),
])
def test_mapping_sweep_attributes_events_per_streak(topology, target, severity,
                                                    fragment, refs):
    cands = _ground_truth_issue_candidates(
        GT_SWEEP, _sweep_frames(topology), SWEEP_CLIFFS, SIGNAL_STAS, None, {AP1}
    )
    assert len(cands) == 3  # streak 3개 전부 근거를 대고 살아남는다
    c = cands[[s["target"] for s in GT_SWEEP["streaks"]].index(target)]
    assert c["issue"]["severity"] == severity
    assert fragment in c["issue"]["msg"]
    assert c["refs"] == refs
    assert STA3 not in c["issue"]["msg"]     # 무관 STA는 어느 streak에도 안 붙는다
    assert AP1 not in c["issue"]["msg"]      # AP는 STA로 매핑되지 않는다
    assert BROADCAST not in c["issue"]["msg"]


@pytest.mark.parametrize("topology,expected_b", [("direct", STA1), ("upstream", STA2)])
def test_mapping_helper_splits_by_target_and_drops_noise(topology, expected_b):
    """매핑 함수 자체의 계약을 한 줄로 고정 — target별 분리 + AP·브로드캐스트·
    비ICMP·GT 밖 target 앵커 배제. 위 스윕이 의존하는 전제다."""
    mapping = _sender_sta_macs_by_target(
        _sweep_frames(topology), SENDER_IP, {AP1}, GT_SWEEP["targets"]
    )
    assert mapping == {TARGET_A: {STA1}, TARGET_B: {expected_b}}


# --------------------------------------------------------------------------
# BSSID 기반 AP 판정 (PR #22 9라운드 — detect_roles가 AP를 못 찾은 캡처)
# --------------------------------------------------------------------------

AP2 = "aa:bb:cc:00:00:05"


def test_bssid_identifies_ap_when_roles_missed_it():
    """beacon/ProbeResp/AssocResp가 없는 data-only 캡처는 detect_roles의 AP 집합이
    비어, 상류 요청의 ta(실제 AP)가 target STA로 매핑된다 — AP는 모든 STA 트래픽에
    끼므로 스코핑이 통째로 무력화된다. 인프라 모드에서 BSSID는 AP의 MAC이므로
    프레임 단위로 AP를 판정할 수 있다 (PR #22 9라운드)."""
    frames = [
        # 상류 다운링크 요청: ta=AP(=BSSID), ra=STA1
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=STA1, bssid=AP1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
        # 업링크 응답: ta=STA1, ra=AP(=BSSID)
        make_frame(number=2, epoch=1005.05, subtype="40", ta=STA1, ra=AP1, bssid=AP1,
                   ip_src=TARGET_IP, ip_dst=SENDER_IP, icmp_type="0"),
        # 무관한 STA2의 로밍 + 재전송 폭주 — 전부 같은 AP를 경유한다
        make_frame(number=3, epoch=1005.1, subtype="11", ta=STA2, ra=AP1, bssid=AP1),
        make_frame(number=4, epoch=1005.2, subtype="40", ta=STA2, ra=AP1, bssid=AP1,
                   retry=True),
        make_frame(number=5, epoch=1005.3, subtype="40", ta=STA2, ra=AP1, bssid=AP1,
                   retry=True),
        make_frame(number=6, epoch=1005.4, subtype="40", ta=STA2, ra=AP1, bssid=AP1,
                   retry=True),
    ]
    # ap_macs 미전달 = detect_roles가 AP를 하나도 못 찾은 상태
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert c["refs"] == [1, 2]                    # STA2 프레임은 스코프 밖
    assert STA1 in c["issue"]["msg"] and AP1 not in c["issue"]["msg"]


def test_frames_between_aps_contribute_no_anchor():
    """고른 상대도 AP면(DS 간 전달 등) 그 프레임은 앵커가 되지 않는다 —
    잘못된 매핑보다 무매핑이 낫다."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", ta=AP1, ra=AP2, bssid=AP1,
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
    ]
    assert _sender_sta_macs_by_target(frames, SENDER_IP, {AP2}) == {}


def test_empty_bssid_keeps_previous_rule():
    """BSSID가 빈 프레임(판정 근거 없음)은 기존 방향 규칙 그대로 — sender가 STA
    자신인 배치에서는 여전히 옳게 매핑된다."""
    frames = [
        make_frame(number=1, epoch=1005.0, subtype="40", ta=STA1, ra=AP1, bssid="",
                   ip_src=SENDER_IP, ip_dst=TARGET_IP, icmp_type="8"),
    ]
    assert _sender_sta_macs_by_target(frames, SENDER_IP) == {TARGET_IP: {STA1}}


# --------------------------------------------------------------------------
# 브로드캐스트 해제 프레임을 STA 스코프 증거에 포함 (PR #22 12라운드 — Codex P1)
# --------------------------------------------------------------------------


def test_broadcast_ap_deauth_counts_as_roaming_evidence_for_mapped_sta():
    """AP가 매핑된 STA로 브로드캐스트 Deauth/Disassoc(ta=AP, ra=브로드캐스트)를
    보내면 기존 STA-MAC 술어(ta/ra ∈ sta_macs)에 안 걸린다 — ra가 브로드캐스트라
    sta_macs 어디에도 없기 때문이다. 그 STA에 실제로 영향을 미치는 방송 해제인데도
    스코프에서 빠지면(창 안에 다른 이벤트가 없을 때) '무선 이상 징후 없음'으로
    오판된다(수정 전 RED: medium)."""
    frames = [
        # sta_macs={STA1} 매핑 앵커 — bssid=AP1(make_frame 기본값)이 sta_bssids를 채운다.
        _ping_anchor(number=1, epoch=1005.0),
        # STA1의 AP(AP1)가 보낸 브로드캐스트 DeAuth.
        make_frame(number=2, epoch=1005.3, ta=AP1, ra=BROADCAST, bssid=AP1, subtype="12"),
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert c["refs"] == [2]


def test_broadcast_deauth_from_unrelated_ap_is_excluded():
    """이 STA와 무관한 다른 AP(다른 BSSID)의 브로드캐스트 Deauth는 sta_bssids에
    없어 스코프에 포함되지 않는다 — 오귀속 방지가 유지됨을 확인."""
    frames = [
        _ping_anchor(number=1, epoch=1005.0),  # sta_bssids={AP1}
        make_frame(number=2, epoch=1005.3, ta=AP2, ra=BROADCAST, bssid=AP2, subtype="12"),
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "이상 징후 없음" in c["issue"]["msg"]
    assert 2 not in c["refs"]


def test_mapping_failure_path_unaffected_by_broadcast_deauth_scoping():
    """매핑 실패(전체 무선 기준) 경로는 애초에 브로드캐스트 해제를 배제하지 않으므로
    이번 수정과 무관 — 무수정 통과로 회귀 확인."""
    frames = [
        make_frame(number=1, epoch=1005.3, ta=AP1, ra=BROADCAST, bssid=AP1, subtype="12"),
    ]
    cands = _ground_truth_issue_candidates(GT_NO_MATCH, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["issue"]["severity"] == "medium"
    assert "로밍/해제 1건" in c["issue"]["msg"]
    assert "매핑 불가" in c["issue"]["msg"]
    assert c["refs"] == [1]
