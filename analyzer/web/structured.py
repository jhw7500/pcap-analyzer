"""웹 시각화용 structured 데이터 생성 함수 모음.

pipeline.run_analysis가 오케스트레이션 중 호출한다. 각 함수는 frames+roles
(필요 시 FrameIndex)를 받아 UI가 소비하는 중첩 dict를 반환한다.
"""

from collections import defaultdict
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

    # MAC ↔ IP 매핑 — 관찰된 IP 양측 추출:
    #   송신(TA=mac)의 ip.src + 수신(RA=mac)의 ip.dst
    # 단방향 캡처에서 한 쪽만 잡히는 케이스를 보완하기 위해 양쪽 모두 본다.
    # broadcast/multicast/unspecified는 제외
    def _is_special_ip(ip: str) -> bool:
        if ip in ("", "0.0.0.0", "255.255.255.255", "::"):
            return True
        if ip.lower().startswith("ff") and ":" in ip:  # IPv6 multicast
            return True
        try:
            first = int(ip.split(".")[0])
            if 224 <= first <= 239:  # IPv4 multicast
                return True
        except (ValueError, IndexError):
            pass
        return False

    def _split_ips(raw: str):
        # tshark는 같은 필드의 multi-value를 콤마로 join해서 반환할 수 있음
        for ip in raw.split(","):
            ip = ip.strip()
            if ip and not _is_special_ip(ip):
                yield ip

    # 빈도 기반 IP 후보 수집:
    #   TA=mac frame의 ip.src   → 송신측 자기 IP (가장 신뢰) — 가중치 2
    #   RA=mac frame의 ip.dst   → 수신측 자기 IP (보조 신호) — 가중치 1
    # 빈도 ↓ 정렬 후 상위 N개만 노출. forwarded/broadcast 잔재 제거 효과.
    from collections import Counter
    dev_ip_counts: Dict[str, "Counter[str]"] = {}
    for f in frames:
        if f.ta and f.ip_src:
            for ip in _split_ips(f.ip_src):
                dev_ip_counts.setdefault(f.ta, Counter())[ip] += 2
        if f.ra and f.ip_dst:
            for ip in _split_ips(f.ip_dst):
                dev_ip_counts.setdefault(f.ra, Counter())[ip] += 1

    # 상위 후보 선별: 가장 빈도 높은 IP의 5% 미만은 노이즈로 간주해 제외
    dev_ips: Dict[str, list] = {}
    for mac, ctr in dev_ip_counts.items():
        if not ctr:
            continue
        top = ctr.most_common(1)[0][1]
        threshold = max(2, top * 0.05)
        kept = [ip for ip, cnt in ctr.most_common() if cnt >= threshold]
        dev_ips[mac] = kept[:5]  # 안전 상한 5개

    devices = []
    for mac, info in sorted(roles.items(), key=lambda x: x[1]["name"]):
        devices.append(
            {
                "mac": mac,
                "role": info["role"],
                "name": info["name"],
                "count": info["count"],
                "ips": dev_ips.get(mac, []),  # 빈도순 (가장 자주 보이는 IP가 첫번째)
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


def _retry_per_sec(device_frames: List[Frame]) -> List[Dict[str, Any]]:
    """장치(ta)의 송신 프레임을 초 단위로 묶어 retry%를 집계한다.

    각 초의 {retry 프레임 수, 전체 프레임 수, retry_pct}를 epoch 오름차순으로 반환.
    rssi 유무와 무관하게 그 장치가 송신한 모든 프레임이 분모(total)에 들어간다
    (retry는 rssi 없는 프레임에도 set될 수 있으므로).
    """
    by_sec: Dict[int, Dict[str, int]] = defaultdict(lambda: {"retry": 0, "total": 0})
    for f in device_frames:
        if f.epoch is None:  # epoch 없는 프레임이 build 전체를 깨지 않도록 방어.
            continue
        b = by_sec[int(f.epoch)]
        b["total"] += 1
        if f.retry:  # Frame.retry는 bool — truthy면 재전송. None/0/False는 비-retry로 본다.
            b["retry"] += 1
    return [
        {
            "epoch": sec,
            "retry": b["retry"],
            "total": b["total"],
            "retry_pct": round(b["retry"] * 100.0 / b["total"], 1) if b["total"] else 0.0,
        }
        for sec, b in sorted(by_sec.items())
    ]


def _structured_signal(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index
) -> Dict[str, Any]:
    """signal_quality + per_second 데이터를 시계열용으로 구조화.

    STA와 AP를 모두 포함한다. monitor adapter가 받은 각 노드 송신 프레임의
    radiotap RSSI = "그 노드가 송신한 신호의 (캡처 위치 기준) 수신 세기".
    AP가 송신한 다운링크 frame의 RSSI도 의미가 있어 별도 버킷 `aps`에 저장.
    """
    result: Dict[str, Any] = {"stas": {}, "aps": {}}

    for mac, info in roles.items():
        role = info.get("role")
        if role not in ("STA", "AP"):
            continue
        name = info["name"]
        if index:
            device_frames = index.by_ta.get(mac, [])
        else:
            device_frames = [f for f in frames if f.ta == mac]
        tx_frames = [f for f in device_frames if f.rssi_first is not None]

        rssi_timeline = [
            {"epoch": f.epoch, "rssi": f.rssi_first, "mcs": f.mcs_int}
            for f in tx_frames
        ]
        rssi_values = [f.rssi_first for f in tx_frames if f.rssi_first is not None]
        entry = {
            "mac": mac,
            "rssi_timeline": rssi_timeline,
            "rssi_min": min(rssi_values, default=None),
            "rssi_max": max(rssi_values, default=None),
            "rssi_avg": round(sum(rssi_values) / len(rssi_values), 1)
            if rssi_values
            else None,
            "frame_count": len(tx_frames),
            # 장치별 초당 retry% (송신 프레임 전체 기준 — rssi 유무 무관).
            "retry_timeline": _retry_per_sec(device_frames),
        }
        bucket = "stas" if role == "STA" else "aps"
        result[bucket][name] = entry

    return result


def _ping_per_sec(full_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """ping outcome을 초 단위로 묶어 전체/장치별 loss%·평균 RTT를 집계한다.

    NOTE: 프론트 `computePingTimeline`(static/js/timeline.js)이 동일 로직을 미러링한다
    (기존 분석엔 이 필드가 없어 full_list로 즉석 계산). bucketing 규칙(어떤 status를
    loss로 셀지 등)을 바꾸면 양쪽을 함께 갱신할 것.

    각 초: 전체 {loss, matched, total, loss_pct, avg_rtt} + 장치(STA)별 동일 지표(by_dev).
    by_dev 키는 _sta_of가 IP↔장치 학습으로 식별한 장치명(미상이면 IP/'?').
    hover에서 그 시점 어느 STA가 손실/지연 주범인지 분해해 보여주기 위함.
    matched=정상 응답, loss/loss_gap=손실. 그 외 status는 무시.
    """
    def _blank() -> Dict[str, Any]:
        return {"loss": 0, "matched": 0, "rtt_sum": 0.0, "rtt_count": 0}

    # ping의 다수(역방향·seq-gap 추정손실)는 src/dst MAC이 비어 장치를 못 가른다.
    # src/dst IP는 항상 있으므로, MAC이 있는 항목에서 IP→장치명을 학습해 IP로 식별한다.
    # (값은 MAC이 아니라 장치명 문자열 — 예: "STA1(aa)")
    ip_to_name: Dict[str, str] = {}
    for p in full_list:
        if p.get("src") and p.get("src_mac"):
            ip_to_name[p["src"]] = p["src_mac"]
        if p.get("dst") and p.get("dst_mac"):
            ip_to_name[p["dst"]] = p["dst_mac"]

    def _sta_of(p: Dict[str, Any]) -> str:
        # ping 상대 STA = src/dst 중 STA로 매핑되는 IP의 장치명.
        for ip in (p.get("dst"), p.get("src")):
            dev = ip_to_name.get(ip)
            if dev and dev.startswith("STA"):
                return dev
        # STA 매핑 실패 시 AP가 아닌 IP를 STA 후보로(IP 그대로 표시), 끝내 없으면 '?'.
        # → by_dev 키에 IP/'?' 가 섞일 수 있다. 프론트는 staNames/apNames(장치명)만
        #   hover에 펼치므로 IP/'?' 키는 hover에서 빠진다(전체 집계 agg에는 포함).
        for ip in (p.get("dst"), p.get("src")):
            if ip and not ip_to_name.get(ip, "").startswith("AP"):
                return ip
        return "?"

    secs: Dict[int, Dict[str, Any]] = {}
    for p in full_list:
        epoch = p.get("epoch")
        if not isinstance(epoch, (int, float)):
            continue
        status = p.get("status")
        if status == "matched":
            is_loss = False
        elif status in ("loss", "loss_gap"):
            is_loss = True
        else:
            continue
        sec = int(epoch)
        bucket = secs.setdefault(sec, {"agg": _blank(), "by_dev": defaultdict(_blank)})
        dev = _sta_of(p)
        for b in (bucket["agg"], bucket["by_dev"][dev]):
            if is_loss:
                b["loss"] += 1
            else:
                b["matched"] += 1
                rtt = p.get("rtt_ms")
                if isinstance(rtt, (int, float)):
                    b["rtt_sum"] += rtt
                    b["rtt_count"] += 1

    def _summary(b: Dict[str, Any]) -> Dict[str, Any]:
        total = b["loss"] + b["matched"]
        return {
            "loss": b["loss"],
            "matched": b["matched"],
            "total": total,
            "loss_pct": round(b["loss"] * 100.0 / total, 1) if total else 0.0,
            # rtt_count(실제 RTT 누적 횟수)를 분모로 — matched 중 rtt_ms 없는 게 있어도 왜곡 없음.
            "avg_rtt": round(b["rtt_sum"] / b["rtt_count"], 2) if b["rtt_count"] else None,
        }

    out: List[Dict[str, Any]] = []
    for sec in sorted(secs):
        bucket = secs[sec]
        row = {"epoch": sec, **_summary(bucket["agg"])}
        row["by_dev"] = {dev: _summary(b) for dev, b in bucket["by_dev"].items()}
        out.append(row)
    return out


def _structured_ping(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    ping = build_ping_matches(frames, roles, PING_MATCH_WINDOW_SEC)
    ping["timeline"] = _ping_per_sec(ping.get("full_list", []))
    return ping


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


def _structured_diagnosis(
    structured: Dict[str, Any], frames: List[Frame] = None, index=None
) -> Dict[str, Any]:
    """구조화된 종합 진단 — 네트워크 건강도 + STA별 상세 + 문제점 목록.

    각 issue/sta_diag issue에는 실제 증거에서 소싱한 frame_refs(stable tshark
    frame.number)와 time_window를 부착한다(근거 없는 결론 0건). frames/index가
    제공되지 않으면 retry 버킷·약신호 프레임 근거를 소싱할 수 없으므로, 해당
    issue는 근거를 댈 수 없으면 드롭한다(근거 없는 결론 금지).
    """
    from . import evidence as ev

    ov = structured.get("overview", {})
    ping = structured.get("ping", {})
    roaming = structured.get("roaming", {})
    signal = structured.get("signal", {})
    device_stats = structured.get("device_stats", {})
    delays = structured.get("delay_zones", {})
    anomalies = structured.get("anomaly_frames", {})

    frames = frames or []
    ping_losses = ping.get("losses", [])

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

        def _add_issue(issue, refs, window, signal_type=None):
            # 근거(frame_refs+time_window)를 댈 수 있을 때만 issue 채택.
            # signal_type은 causality.build_correlations가 종합 결론을
            # 만들 때 신호 분류 키로 사용한다(기존 소비자는 무시 가능).
            if ev._attach(issue, refs, window):
                if signal_type:
                    issue["signal_type"] = signal_type
                issues.append(issue)

        if sta_retry > 25:
            refs, window = ev.retry_bucket_evidence(mac, index)
            _add_issue(
                {
                    "severity": "high",
                    "msg": f"Retry율 {sta_retry}% (임계치 25% 초과)",
                    "action": "TX power 또는 안테나 확인, 로밍 임계값 조정",
                },
                refs, window, signal_type="high_retry",
            )
        elif sta_retry > 15:
            refs, window = ev.retry_bucket_evidence(mac, index)
            _add_issue(
                {
                    "severity": "medium",
                    "msg": f"Retry율 {sta_retry}%",
                    "action": "채널 혼잡도 확인",
                },
                refs, window, signal_type="high_retry",
            )
        if rssi_avg is not None and rssi_avg < -70:
            refs, window = ev.weak_rssi_evidence(mac, -70, frames, index)
            _add_issue(
                {
                    "severity": "high",
                    "msg": f"RSSI 평균 {rssi_avg}dBm (약함)",
                    "action": "AP 위치 조정 또는 TX power 증가",
                },
                refs, window, signal_type="weak_rssi",
            )
        elif rssi_avg is not None and rssi_avg < -60:
            refs, window = ev.weak_rssi_evidence(mac, -60, frames, index)
            _add_issue(
                {
                    "severity": "medium",
                    "msg": f"RSSI 평균 {rssi_avg}dBm",
                    "action": "AP 커버리지 확인",
                },
                refs, window, signal_type="weak_rssi",
            )
        if len(sta_slow_roams) > 2:
            refs, window = ev.slow_roaming_evidence(roam_seqs, mac)
            _add_issue(
                {
                    "severity": "high",
                    "msg": f"느린 로밍 {len(sta_slow_roams)}회 (>100ms)",
                    "action": "802.11r/k/v 설정 확인, 로밍 히스테리시스 조정",
                },
                refs, window, signal_type="slow_roaming",
            )
        elif len(sta_roams) > 10:
            refs, window = ev.roaming_evidence(roam_seqs, mac)
            _add_issue(
                {
                    "severity": "medium",
                    "msg": f"잦은 로밍 {len(sta_roams)}회",
                    "action": "로밍 트리거 RSSI 임계값 재설정",
                },
                refs, window, signal_type="frequent_roaming",
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

    def _add_net_issue(issue, refs, window, signal_type=None):
        # 네트워크 레벨 issue도 근거를 댈 수 있을 때만 채택. signal_type은
        # causality.build_correlations가 STA cluster에 cross-attach할 신호
        # 종류를 식별하는 키로 사용한다(기존 소비자는 무시 가능).
        if ev._attach(issue, refs, window):
            if signal_type:
                issue["signal_type"] = signal_type
            all_issues.append(issue)

    if retry_pct > 15:
        refs, window = ev.network_retry_evidence(frames, index)
        _add_net_issue(
            {
                "severity": "high",
                "category": "Retry",
                "msg": f"네트워크 전체 Retry율 {retry_pct}%",
                "action": "채널 간섭 또는 AP 과부하 확인",
            },
            refs, window, signal_type="high_retry",
        )
    if loss_pct > 5:
        refs, window = ev.ping_loss_evidence(ping_losses)
        _add_net_issue(
            {
                "severity": "high",
                "category": "Ping",
                "msg": f"Ping Loss {loss_pct}%",
                "action": "네트워크 안정성 점검, 로밍 구간 확인",
            },
            refs, window, signal_type="high_loss",
        )
    if len(slow_roams) > 5:
        refs, window = ev.slow_roaming_evidence(roam_seqs)
        _add_net_issue(
            {
                "severity": "high",
                "category": "로밍",
                "msg": f"느린 로밍 {len(slow_roams)}회",
                "action": "802.11r Fast BSS Transition 활성화",
            },
            refs, window, signal_type="slow_roaming",
        )
    anom_events = anomalies.get("anomalies", [])
    for a in anom_events:
        # 이상 프레임은 집계 카운트만 가지므로 같은 종류 프레임을 직접 근거로 소싱.
        _add_net_issue(
            {
                "severity": a.get("severity", "medium"),
                "category": a.get("type", ""),
                "msg": a.get("description", ""),
                "action": a.get("recommendation", ""),
            },
            *ev.anomaly_evidence(a.get("type", ""), frames),
            signal_type="anomaly",
        )
    delay_zones = delays.get("delay_zones", [])
    if len(delay_zones) > 3:
        # 지연 구간들의 epoch 범위 + 그 안의 ping loss request 프레임을 근거로.
        dz_epochs = []
        for z in delay_zones:
            for k in ("start_epoch", "end_epoch", "epoch"):
                v = z.get(k)
                if isinstance(v, (int, float)):
                    dz_epochs.append(float(v))
        dz_window = ev._window(dz_epochs)
        dz_refs, _ = ev.ping_loss_evidence(ping_losses)
        if not dz_refs:
            # ping loss 근거가 없으면 로밍을 fallback으로 쓰되, refs와 window를
            # 함께 받아 일치시킨다. 로밍 프레임의 epoch은 지연 구간 window 밖일 수
            # 있어, window를 교체하지 않으면 '증거 보기' 줌 범위에서 필터링돼 안 보인다.
            dz_refs, dz_window = ev.roaming_evidence(roam_seqs)
        _add_net_issue(
            {
                "severity": "medium",
                "category": "지연",
                "msg": f"지연 구간 {len(delay_zones)}건 탐지",
                "action": "로밍/retry 상관관계 확인",
            },
            dz_refs, dz_window, signal_type="delay_zone",
        )
    for sd in sta_diags:
        for issue in sd["issues"]:
            # STA issue는 이미 frame_refs/time_window를 동반 — 그대로 승격.
            all_issues.append(
                {
                    "severity": issue["severity"],
                    "category": sd["name"],
                    "msg": issue["msg"],
                    "action": issue["action"],
                    "frame_refs": issue.get("frame_refs", []),
                    "time_window": issue.get("time_window"),
                }
            )

    severity_order = {"high": 0, "medium": 1, "low": 2}
    all_issues.sort(key=lambda x: severity_order.get(x["severity"], 3))

    result = {
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
    # 다중 신호 종합 결론(추가형) — 기존 issues/sta_diags는 그대로 두고
    # 시간 동기 결합 결론만 새 키로 노출. 소비자가 모르면 그냥 무시한다.
    # 함수 안에서 import: 모듈 top-level은 analyzer.core.modules → analyzer.web
    # 순서로 evaluate되는데 causality는 analyzer.core.modules 아래에 있어
    # 패키지 초기화 시점 순환 위험이 있는 위치. 함수 호출 시점 import로
    # 측면 의존만 유지(런타임 비용 무시 가능). build_correlations가 어떤
    # 이유로든 실패해도 핵심 진단(issues/sta_diags)은 그대로 반환되도록
    # 빈 리스트 fallback으로 isolate.
    try:
        from analyzer.core.modules.causality import build_correlations
        result["correlations"] = build_correlations(result)
    except Exception as exc:
        # 핵심 진단을 보호하기 위해 bare-except로 흡수하되, 무음 실패는 디버깅을
        # 어렵게 만든다 — WARN 레벨로 traceback과 함께 남겨 회귀 발견 가능하게.
        import logging
        logging.getLogger(__name__).warning(
            "build_correlations failed; correlations 빈 리스트로 fallback: %s",
            exc, exc_info=True,
        )
        result["correlations"] = []
    return result
