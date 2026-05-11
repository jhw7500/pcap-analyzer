"""웹 시각화용 structured 데이터 생성 함수 모음.

pipeline.run_analysis가 오케스트레이션 중 호출한다. 각 함수는 frames+roles
(필요 시 FrameIndex)를 받아 UI가 소비하는 중첩 dict를 반환한다.
"""

from typing import Any, Dict, List

from ..core.models import Frame
from ..core.ping_matching import PING_MATCH_WINDOW_SEC, build_ping_matches


def _structured_overview(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], section
) -> Dict[str, Any]:
    """overview 모듈의 텍스트 출력을 구조화된 dict로 변환."""
    n = len(frames)
    if n == 0:
        return {"total_frames": 0}

    from collections import Counter

    proto_counts = Counter(f.protocol for f in frames)
    subtype_counts = Counter(f.subtype for f in frames)
    retry_count = sum(1 for f in frames if f.retry)

    devices = []
    for mac, info in sorted(roles.items(), key=lambda x: x[1]["name"]):
        devices.append(
            {
                "mac": mac,
                "role": info["role"],
                "name": info["name"],
                "count": info["count"],
            }
        )

    return {
        "total_frames": n,
        "duration_sec": round(frames[-1].epoch - frames[0].epoch, 1),
        "time_start": frames[0].timestamp,
        "time_end": frames[-1].timestamp,
        "retry_count": retry_count,
        "retry_pct": round(retry_count * 100.0 / n, 2) if n else 0,
        "protocol_dist": dict(proto_counts.most_common(20)),
        "subtype_dist": dict(subtype_counts.most_common(20)),
        "devices": devices,
    }


def _structured_signal(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index
) -> Dict[str, Any]:
    """signal_quality + per_second 데이터를 시계열용으로 구조화."""
    sta_macs = [m for m, r in roles.items() if r["role"] == "STA"]
    result: Dict[str, Any] = {"stas": {}}

    for sta in sta_macs:
        name = roles[sta]["name"]
        if index:
            tx_frames = [
                f for f in index.by_ta.get(sta, []) if f.rssi_first is not None
            ]
        else:
            tx_frames = [f for f in frames if f.ta == sta and f.rssi_first is not None]

        rssi_timeline = [
            {"epoch": f.epoch, "rssi": f.rssi_first, "mcs": f.mcs_int}
            for f in tx_frames
        ]
        rssi_values = [f.rssi_first for f in tx_frames if f.rssi_first is not None]
        result["stas"][name] = {
            "mac": sta,
            "rssi_timeline": rssi_timeline,
            "rssi_min": min(rssi_values, default=None),
            "rssi_max": max(rssi_values, default=None),
            "rssi_avg": round(sum(rssi_values) / len(rssi_values), 1)
            if rssi_values
            else None,
            "frame_count": len(tx_frames),
        }

    return result


def _structured_ping(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    return build_ping_matches(frames, roles, PING_MATCH_WINDOW_SEC)


def _structured_roaming(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """roaming 이벤트를 구조화."""
    from ..core.detector import mac_name

    roaming_frames = [f for f in frames if f.is_roaming_related]
    sta_macs = {mac for mac, role in roles.items() if role.get("role") == "STA"}

    sequences = []
    auth_events: Dict[str, Frame] = {}
    for frame in roaming_frames:
        if frame.subtype == "11" and frame.ta in sta_macs:
            auth_events[frame.ta] = frame
        elif frame.subtype in ("0", "2") and frame.ta in sta_macs:
            auth_frame = auth_events.get(frame.ta)
            if auth_frame is None:
                continue
            gap_ms = (frame.epoch - auth_frame.epoch) * 1000
            sequences.append(
                {
                    "sta": frame.ta,
                    "sta_name": mac_name(frame.ta, roles),
                    "ap": frame.ra,
                    "ap_name": mac_name(frame.ra, roles),
                    "auth_epoch": auth_frame.epoch,
                    "assoc_epoch": frame.epoch,
                    "auth_fnum": auth_frame.number,
                    "assoc_fnum": frame.number,
                    "gap_ms": round(gap_ms, 1),
                    "assoc_type": frame.subtype_name,
                    "is_slow": gap_ms > 100,
                }
            )

    return {
        "roaming_frame_count": len(roaming_frames),
        "sequences": sequences,
    }


def _structured_per_second(frames: List[Frame]) -> Dict[str, Any]:
    """초당 프레임 수 시계열."""
    if not frames:
        return {"timeline": []}
    from collections import Counter

    sec_counts = Counter(int(f.epoch) for f in frames)
    retry_counts = Counter(int(f.epoch) for f in frames if f.retry)
    start = min(sec_counts)
    end = max(sec_counts)
    timeline = []
    for sec in range(start, end + 1):
        timeline.append(
            {
                "epoch": sec,
                "total": sec_counts.get(sec, 0),
                "retry": retry_counts.get(sec, 0),
            }
        )
    return {"timeline": timeline}


def _structured_device_stats(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index
) -> Dict[str, Any]:
    """장치별 프레임 타입/서브타입/MCS/RSSI/시간대별 통계."""
    from collections import Counter
    from ..core.models import SUBTYPE_NAMES

    result = {}
    for mac, info in roles.items():
        if index:
            dev_frames = index.by_ta.get(mac, []) + index.by_ra.get(mac, [])
        else:
            dev_frames = [f for f in frames if f.ta == mac or f.ra == mac]

        if not dev_frames:
            continue

        type_dist = Counter(f.frame_type for f in dev_frames)
        subtype_dist = Counter(f.subtype for f in dev_frames)
        retry_count = sum(1 for f in dev_frames if f.retry)

        subtype_named = {}
        for st, cnt in subtype_dist.most_common(20):
            name = SUBTYPE_NAMES.get(st, f"type={st}")
            subtype_named[name] = cnt

        tx_frames = [f for f in dev_frames if f.ta == mac]
        mcs_dist = Counter(f.mcs_int for f in tx_frames if f.mcs_int is not None)
        mcs_named = {str(k): v for k, v in sorted(mcs_dist.items())}

        # PHY 모드별 분리: HT/VHT/HE/EHT는 MCS index, Legacy는 Mbps rate.
        # 한 디바이스가 mode를 섞어 송신하는 경우(예: HE 데이터 + 6Mbps mgmt)도 정직하게 표현.
        phy_buckets: Dict[str, "Counter[str]"] = {
            "HT": Counter(), "VHT": Counter(), "HE": Counter(),
            "EHT": Counter(), "Legacy": Counter(),
        }
        phy_frame_count: "Counter[str]" = Counter()
        for f in tx_frames:
            phy = getattr(f, "mcs_phy", "") or ""
            if phy in ("HT", "VHT", "HE", "EHT"):
                m = f.mcs_int
                if m is not None:
                    phy_buckets[phy][str(m)] += 1
                    phy_frame_count[phy] += 1
            else:
                rate = (getattr(f, "data_rate", "") or "").split(",")[0].strip()
                if rate:
                    phy_buckets["Legacy"][rate] += 1
                    phy_frame_count["Legacy"] += 1
        mcs_by_phy = {
            phy: dict(sorted(c.items(), key=lambda kv: float(kv[0])))
            for phy, c in phy_buckets.items() if c
        }
        phy_summary = dict(phy_frame_count)

        rssis = [f.rssi_first for f in tx_frames if f.rssi_first is not None]
        rssi_stats = {}
        if rssis:
            rssi_sorted = sorted(rssis)
            rssi_stats = {
                "min": rssi_sorted[0],
                "max": rssi_sorted[-1],
                "avg": round(sum(rssis) / len(rssis), 1),
                "count": len(rssis),
            }

        per_bucket = []
        retry_peaks: list = []
        if dev_frames:
            start_epoch = int(dev_frames[0].epoch)
            end_epoch = int(dev_frames[-1].epoch)
            bucket_size = 10  # 10초 구간
            per_bucket = []
            for bucket_start in range(start_epoch, end_epoch + 1, bucket_size):
                bucket_end = bucket_start + bucket_size
                bucket_frames = [
                    f for f in dev_frames if bucket_start <= f.epoch < bucket_end
                ]
                total = len(bucket_frames)
                retries = sum(1 for f in bucket_frames if f.retry)
                # bucket별 MCS / PHY 통계 (송신 프레임 기준)
                bucket_tx = [f for f in bucket_frames if f.ta == mac]
                phy_mcs_counts: "Counter[str]" = Counter()
                legacy_counts: "Counter[str]" = Counter()
                phy_mode_dist: "Counter[str]" = Counter()
                mcs_sum, mcs_n = 0, 0
                for f in bucket_tx:
                    phy = getattr(f, "mcs_phy", "") or ""
                    if phy in ("HT", "VHT", "HE", "EHT"):
                        m = f.mcs_int
                        if m is not None:
                            phy_mcs_counts[f"{phy} MCS{m}"] += 1
                            phy_mode_dist[phy] += 1
                            mcs_sum += m
                            mcs_n += 1
                    else:
                        rate = (getattr(f, "data_rate", "") or "").split(",")[0].strip()
                        if rate:
                            legacy_counts[f"Legacy {rate}Mbps"] += 1
                            phy_mode_dist["Legacy"] += 1
                combined = phy_mcs_counts + legacy_counts
                mcs_breakdown = ", ".join(
                    f"{k}×{v:,}" for k, v in combined.most_common(5)
                )
                avg_mcs = round(mcs_sum / mcs_n, 1) if mcs_n else None
                tx_total = len(bucket_tx)
                legacy_n = sum(legacy_counts.values())
                legacy_pct = round(legacy_n * 100 / tx_total, 1) if tx_total else 0
                per_bucket.append(
                    {
                        "epoch": bucket_start,
                        "total": total,
                        "retry": retries,
                        "retry_pct": round(retries * 100 / total, 1) if total else 0,
                        "mcs_breakdown": mcs_breakdown,
                        "avg_mcs": avg_mcs,
                        "legacy_pct": legacy_pct,
                        "tx_total": tx_total,
                        "phy_mode_dist": dict(phy_mode_dist),
                    }
                )

            # retry 피크 구간 zoom-in (top 3 retry%, total>50인 bucket)
            retry_peaks = []
            candidate_peaks = sorted(
                [b for b in per_bucket if b.get("total", 0) > 50],
                key=lambda b: -b.get("retry_pct", 0),
            )[:3]
            for pk in candidate_peaks:
                if pk.get("retry_pct", 0) < 10:
                    break
                pk_start = pk["epoch"]
                pk_end = pk_start + bucket_size
                pk_frames = [
                    f for f in dev_frames if pk_start <= f.epoch < pk_end
                ]
                sub_buckets = []
                for sub_start in range(pk_start, pk_end):
                    sub_end = sub_start + 1
                    sub = [f for f in pk_frames if sub_start <= f.epoch < sub_end]
                    if not sub:
                        continue
                    sub_total = len(sub)
                    sub_retry = sum(1 for f in sub if f.retry)
                    sub_tx = [f for f in sub if f.ta == mac]
                    sub_mcs_counts: "Counter[str]" = Counter()
                    for f in sub_tx:
                        phy = getattr(f, "mcs_phy", "") or ""
                        if phy in ("HT", "VHT", "HE", "EHT") and f.mcs_int is not None:
                            sub_mcs_counts[f"{phy} MCS{f.mcs_int}"] += 1
                        else:
                            rate = (
                                getattr(f, "data_rate", "") or ""
                            ).split(",")[0].strip()
                            if rate:
                                sub_mcs_counts[f"Legacy {rate}Mbps"] += 1
                    sub_breakdown = ", ".join(
                        f"{k}×{v:,}" for k, v in sub_mcs_counts.most_common(4)
                    )
                    sub_buckets.append({
                        "epoch": sub_start,
                        "total": sub_total,
                        "retry": sub_retry,
                        "retry_pct": round(sub_retry * 100 / sub_total, 1) if sub_total else 0,
                        "tx_total": len(sub_tx),
                        "mcs_breakdown": sub_breakdown,
                    })
                retry_peaks.append({
                    "start": pk_start,
                    "duration": bucket_size,
                    "total": pk.get("total", 0),
                    "retry": pk.get("retry", 0),
                    "retry_pct": pk.get("retry_pct", 0),
                    "sub_buckets": sub_buckets,
                })

        result[info["name"]] = {
            "mac": mac,
            "role": info["role"],
            "total_frames": len(dev_frames),
            "tx_frames": len(tx_frames),
            "type_dist": dict(type_dist),
            "subtype_dist": subtype_named,
            "retry_count": retry_count,
            "retry_pct": round(retry_count * 100 / len(dev_frames), 1)
            if dev_frames
            else 0,
            "mcs_dist": mcs_named,
            "mcs_by_phy": mcs_by_phy,
            "phy_summary": phy_summary,
            "rssi_stats": rssi_stats,
            "per_bucket": per_bucket if dev_frames else [],
            "retry_peaks": retry_peaks if dev_frames else [],
        }
    return result


def _structured_diagnosis(structured: Dict[str, Any]) -> Dict[str, Any]:
    """구조화된 종합 진단 — 네트워크 건강도 + STA별 상세 + 문제점 목록."""
    ov = structured.get("overview", {})
    ping = structured.get("ping", {})
    roaming = structured.get("roaming", {})
    signal = structured.get("signal", {})
    device_stats = structured.get("device_stats", {})
    delays = structured.get("delay_zones", {})
    anomalies = structured.get("anomaly_frames", {})

    total_frames = ov.get("total_frames", 0)
    retry_pct = ov.get("retry_pct", 0)
    ping_stats = ping.get("stats", {})
    loss_pct = ping_stats.get("loss_pct", 0)
    roam_seqs = roaming.get("sequences", [])
    slow_roams = [s for s in roam_seqs if s.get("is_slow")]

    retry_score = max(0, 100 - retry_pct * 5)
    loss_score = max(0, 100 - loss_pct * 10)
    roam_score = 100
    if len(roam_seqs) > 0:
        slow_ratio = len(slow_roams) / len(roam_seqs) * 100
        roam_score = max(0, 100 - slow_ratio * 2)

    health_score = round(retry_score * 0.3 + loss_score * 0.4 + roam_score * 0.3)
    if health_score >= 80:
        health_grade = "양호"
        health_color = "green"
    elif health_score >= 60:
        health_grade = "주의"
        health_color = "yellow"
    else:
        health_grade = "위험"
        health_color = "red"

    sta_diags = []
    stas = signal.get("stas", {})
    for sta_name, sta_info in stas.items():
        mac = sta_info.get("mac", "")
        ds = device_stats.get(sta_name, {})
        sta_retry = ds.get("retry_pct", 0)
        rssi_avg = sta_info.get("rssi_avg")
        rssi_min = sta_info.get("rssi_min")

        sta_roams = [s for s in roam_seqs if s.get("sta") == mac]
        sta_slow_roams = [s for s in sta_roams if s.get("is_slow")]

        s_retry = max(0, 100 - sta_retry * 5)
        s_rssi = 100
        if rssi_avg is not None:
            s_rssi = max(0, min(100, (rssi_avg + 90) * 2.5))
        s_roam = (
            100
            if not sta_roams
            else max(0, 100 - len(sta_slow_roams) / max(len(sta_roams), 1) * 200)
        )
        s_overall = round(s_retry * 0.35 + s_rssi * 0.35 + s_roam * 0.3)

        issues = []
        if sta_retry > 25:
            issues.append(
                {
                    "severity": "high",
                    "msg": f"Retry율 {sta_retry}% (임계치 25% 초과)",
                    "action": "TX power 또는 안테나 확인, 로밍 임계값 조정",
                }
            )
        elif sta_retry > 15:
            issues.append(
                {
                    "severity": "medium",
                    "msg": f"Retry율 {sta_retry}%",
                    "action": "채널 혼잡도 확인",
                }
            )
        if rssi_avg is not None and rssi_avg < -70:
            issues.append(
                {
                    "severity": "high",
                    "msg": f"RSSI 평균 {rssi_avg}dBm (약함)",
                    "action": "AP 위치 조정 또는 TX power 증가",
                }
            )
        elif rssi_avg is not None and rssi_avg < -60:
            issues.append(
                {
                    "severity": "medium",
                    "msg": f"RSSI 평균 {rssi_avg}dBm",
                    "action": "AP 커버리지 확인",
                }
            )
        if len(sta_slow_roams) > 2:
            issues.append(
                {
                    "severity": "high",
                    "msg": f"느린 로밍 {len(sta_slow_roams)}회 (>100ms)",
                    "action": "802.11r/k/v 설정 확인, 로밍 히스테리시스 조정",
                }
            )
        elif len(sta_roams) > 10:
            issues.append(
                {
                    "severity": "medium",
                    "msg": f"잦은 로밍 {len(sta_roams)}회",
                    "action": "로밍 트리거 RSSI 임계값 재설정",
                }
            )

        sta_diags.append(
            {
                "name": sta_name,
                "mac": mac,
                "score": s_overall,
                "scores": {
                    "retry": round(s_retry),
                    "rssi": round(s_rssi),
                    "roaming": round(s_roam),
                },
                "metrics": {
                    "retry_pct": sta_retry,
                    "rssi_avg": rssi_avg,
                    "rssi_min": rssi_min,
                    "roaming_count": len(sta_roams),
                    "slow_roaming": len(sta_slow_roams),
                    "total_frames": ds.get("total_frames", 0),
                },
                "issues": issues,
            }
        )

    all_issues = []
    if retry_pct > 15:
        all_issues.append(
            {
                "severity": "high",
                "category": "Retry",
                "msg": f"네트워크 전체 Retry율 {retry_pct}%",
                "action": "채널 간섭 또는 AP 과부하 확인",
            }
        )
    if loss_pct > 5:
        all_issues.append(
            {
                "severity": "high",
                "category": "Ping",
                "msg": f"Ping Loss {loss_pct}%",
                "action": "네트워크 안정성 점검, 로밍 구간 확인",
            }
        )
    if len(slow_roams) > 5:
        all_issues.append(
            {
                "severity": "high",
                "category": "로밍",
                "msg": f"느린 로밍 {len(slow_roams)}회",
                "action": "802.11r Fast BSS Transition 활성화",
            }
        )
    anom_events = anomalies.get("anomalies", [])
    for a in anom_events:
        all_issues.append(
            {
                "severity": a.get("severity", "medium"),
                "category": a.get("type", ""),
                "msg": a.get("description", ""),
                "action": a.get("recommendation", ""),
            }
        )
    delay_zones = delays.get("delay_zones", [])
    if len(delay_zones) > 3:
        all_issues.append(
            {
                "severity": "medium",
                "category": "지연",
                "msg": f"지연 구간 {len(delay_zones)}건 탐지",
                "action": "로밍/retry 상관관계 확인",
            }
        )
    for sd in sta_diags:
        for issue in sd["issues"]:
            all_issues.append(
                {
                    "severity": issue["severity"],
                    "category": sd["name"],
                    "msg": issue["msg"],
                    "action": issue["action"],
                }
            )

    severity_order = {"high": 0, "medium": 1, "low": 2}
    all_issues.sort(key=lambda x: severity_order.get(x["severity"], 3))

    return {
        "health": {"score": health_score, "grade": health_grade, "color": health_color},
        "component_scores": {
            "retry": round(retry_score),
            "loss": round(loss_score),
            "roaming": round(roam_score),
        },
        "summary": {
            "total_frames": total_frames,
            "retry_pct": retry_pct,
            "loss_pct": loss_pct,
            "roaming_total": len(roam_seqs),
            "roaming_slow": len(slow_roams),
            "delay_zones": len(delay_zones),
            "anomaly_count": len(anom_events),
        },
        "sta_diags": sta_diags,
        "issues": all_issues,
    }
