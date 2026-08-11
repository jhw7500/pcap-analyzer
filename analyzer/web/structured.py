"""웹 시각화용 structured 데이터 생성 함수 모음.

pipeline.run_analysis가 오케스트레이션 중 호출한다. 각 함수는 frames+roles
(필요 시 FrameIndex)를 받아 UI가 소비하는 중첩 dict를 반환한다.
"""

import math
from collections import Counter, defaultdict
from statistics import median
from typing import Any, Dict, List, Optional

from ..core.channels import ap_channel_map, freq_to_band, freq_to_channel, parse_freq
from ..core.merge import MergeResult
from ..core.models import Frame
from ..core.ping_matching import (
    PING_MATCH_WINDOW_SEC,
    build_ping_matches,
    find_time_streaks,
    ping_losses as _ping_losses,
    ping_pairs as _ping_pairs,
)
from ..core.thresholds import (
    LOSS_DANGER_PCT,
    RETRY_DANGER_PCT,
    ROAM_GAP_DANGER_MS,
    RSSI_DANGER_DBM,
    RSSI_WARN_DBM,
    retry_severity,
    rssi_severity,
)


def is_special_ip(ip: str) -> bool:
    """멀티캐스트·링크로컬·루프백·브로드캐스트·미지정 주소 판정.

    `_structured_overview`의 자기 IP 후보 필터와 `pipeline._derived_ip_filter`의
    mac_filter→ip_filter 유도가 이 규칙을 공유한다 — 한쪽만 넓히면 두 경로가 서로
    다른 "특수 IP" 정의를 쓰게 돼 유도 결과에 링크로컬/루프백 잔재가 섞일 수 있다.
    모듈 밖(pipeline.py)에서도 import해 쓰므로 공개 이름을 쓴다.
    """
    if ip in ("", "0.0.0.0", "255.255.255.255", "::"):
        return True
    if ip.lower().startswith("ff") and ":" in ip:  # IPv6 multicast
        return True
    try:
        octets = ip.split(".")
        first = int(octets[0])
        if 224 <= first <= 239:  # IPv4 multicast
            return True
        if first == 127:  # IPv4 loopback
            return True
        if first == 169 and int(octets[1]) == 254:  # IPv4 link-local
            return True
    except (ValueError, IndexError):
        pass
    return False


def _structured_merge(mr: MergeResult) -> Dict[str, Any]:
    """merge_captures 결과를 프론트향 merge 요약 스키마(structured["merge"])로 변환.

    AGENTS.md상 pipeline.py는 오케스트레이션 전용이고 구조화 스키마 생성은 이
    모듈 소관이라 pipeline.py에서 옮겨왔다(PR #23 리뷰 Finding B). mr.stats는
    항상 **시간 창 적용 전** 값이다 — 시계 정렬·dedup은 창과 무관하게 전체
    구간 기준으로 수행되고(PR #23 리뷰 Finding A), 창은 정렬된 프레임 목록에만
    사후 적용되므로 이 요약도 그 전체 기준 kept/duplicates/coverage를 그대로
    보여준다(창 이후 재계산 아님).
    """
    return {
        "window_ms": mr.stats["window_ms"],
        "duplicates": mr.stats["duplicates"],
        "kept": mr.stats["kept"],
        "coverage": mr.stats["coverage"],
    }


#: 초당 시계열 zero-fill(갭 0 채움)을 허용하는 최대 구간(초). 손상 epoch
#: (0·먼 미래값) 프레임이 섞이면 range()가 수십억 항목으로 팽창하는 경로라
#: (PR #24 Gemini 리뷰 HIGH), 이보다 긴 구간은 관측된 초만 담는 희소
#: 시계열로 폴백해 출력 크기를 프레임 수에 비례시킨다. 정상 스니퍼 배치
#: 테스트(분~시간 단위)는 전부 zero-fill 경로를 탄다.
_SNIFFER_FILL_MAX_SPAN_SEC = 6 * 3600  #: (_structured_per_second도 같은 상한을 공유한다 — 백로그 ③)


def _structured_sniffer_compare(
    mr: MergeResult,
    window_start_epoch: Optional[float] = None,
    window_end_epoch: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """스니퍼 비교 스키마(structured["sniffer_compare"]) 생성 — 스펙 §5.

    소스가 2개 미만이면 None — 비교 대상이 없으니 섹션 자체를 생략한다
    (alignment 전용 merge로 생존 소스가 1개인 경우 포함).

    시계열은 per_source(보정된 epoch) 기준이되, 사용자가 시간 창을 지정한
    분석에서는 pipeline이 window_*_epoch(정렬 보정 후 벽시계 기준, [start,
    end) 반개구간 — pipeline의 defer 창과 동일 의미)를 넘겨 같은 창으로
    잘라낸다 — 나머지 결과가 전부 창 구간만 기술하는데 이 카드만 전체
    캡처를 그리면 오해를 부른다(PR #24 Codex P2). coverage는 시간 창과
    무관한 병합(정렬·dedup) 통계이므로 _structured_merge와 같은 원칙으로
    항상 전체 구간 기준 mr.stats를 재노출한다.

    per_source 계약(analyzer/core/merge.py MergeResult 주석): 여기서 소비하는
    필드는 epoch·retry·rssi뿐 — 셋 다 _MERGEABLE_DECODED_FIELDS에 없어 대표
    필드 차용 오염을 받지 않고, 재번호되는 number는 쓰지 않으므로 병합 전
    스냅샷이 필요 없다(tests/test_sniffer_compare.py의 가드 테스트로 고정).
    """
    if len(mr.per_source) < 2:
        return None
    series: Dict[str, List[Dict[str, Any]]] = {}
    for tag, frames in mr.per_source.items():
        counts: "Counter[int]" = Counter()
        retries: "Counter[int]" = Counter()
        rssi_sum: Dict[int, int] = {}
        rssi_n: Dict[int, int] = {}
        for f in frames:
            # epoch 없는/비유한 프레임 방어 — _structured_per_second와 동일한
            # 이유(int(None)→TypeError, int(nan)→ValueError로 분석 전체 중단).
            if f.epoch is None or not math.isfinite(f.epoch):
                continue
            if window_start_epoch is not None and f.epoch < window_start_epoch:
                continue
            if window_end_epoch is not None and f.epoch >= window_end_epoch:
                continue
            sec = int(f.epoch)
            counts[sec] += 1
            if f.retry:
                retries[sec] += 1
            r = f.rssi_first
            if r is not None:
                rssi_sum[sec] = rssi_sum.get(sec, 0) + r
                rssi_n[sec] = rssi_n.get(sec, 0) + 1
        timeline: List[Dict[str, Any]] = []
        if counts:
            lo, hi = min(counts), max(counts)
            if hi - lo <= _SNIFFER_FILL_MAX_SPAN_SEC:
                secs = range(lo, hi + 1)
            else:
                secs = sorted(counts)
            for sec in secs:
                n = rssi_n.get(sec, 0)
                timeline.append({
                    "epoch": sec,
                    "frames": counts.get(sec, 0),
                    "retry": retries.get(sec, 0),
                    "rssi_avg": round(rssi_sum[sec] / n, 1) if n else None,
                })
        series[tag] = timeline
    cov = mr.stats.get("coverage") or {}
    return {
        "tags": list(mr.per_source.keys()),
        "series": series,
        "coverage": {
            "both": cov.get("both", 0),
            "only": dict(cov.get("only", {})),
            "groups_total": mr.stats.get("kept", 0),
        },
    }


def _structured_overview(
    frames: List[Frame],
    roles: Dict[str, Dict[str, Any]],
    section,
    ap_ch: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """overview 모듈의 텍스트 출력을 구조화된 dict로 변환."""
    n = len(frames)
    if n == 0:
        return {"total_frames": 0}


    proto_counts = Counter(f.protocol for f in frames)
    subtype_counts = Counter(f.subtype for f in frames)
    type_counts = Counter(f.frame_type for f in frames)
    retry_count = sum(1 for f in frames if f.retry)

    # MAC ↔ IP 매핑 — 관찰된 IP 양측 추출:
    #   송신(TA=mac)의 ip.src + 수신(RA=mac)의 ip.dst
    # 단방향 캡처에서 한 쪽만 잡히는 케이스를 보완하기 위해 양쪽 모두 본다.
    # broadcast/multicast/링크로컬/루프백/unspecified는 제외 (is_special_ip)
    def _split_ips(raw: str):
        # tshark는 같은 필드의 multi-value를 콤마로 join해서 반환할 수 있음
        for ip in raw.split(","):
            ip = ip.strip()
            if ip and not is_special_ip(ip):
                yield ip

    # 빈도 기반 IP 후보 수집:
    #   TA=mac frame의 ip.src   → 송신측 자기 IP (가장 신뢰) — 가중치 2
    #   RA=mac frame의 ip.dst   → 수신측 자기 IP (보조 신호) — 가중치 1
    # 빈도 ↓ 정렬 후 상위 N개만 노출. forwarded/broadcast 잔재 제거 효과.
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

    # 채널/밴드 분포 — radiotap.channel.freq 기반. 구형 tshark 등으로 필드가
    # 비면 by_channel이 빈 리스트가 되고 소비자(UI/report)는 조건부 렌더.
    freq_counter: "Counter[int]" = Counter()
    for f in frames:
        freq = parse_freq(getattr(f, "channel_freq", "") or "")
        if freq is not None:
            freq_counter[freq] += 1
    by_channel = [
        {
            "freq": freq,
            "channel": freq_to_channel(freq),
            "band": freq_to_band(freq),
            "frames": cnt,
        }
        for freq, cnt in freq_counter.most_common()
    ]
    if ap_ch is None:
        ap_ch = ap_channel_map(frames, roles)
    ap_channels = {
        mac: {
            "name": roles[mac]["name"],
            "freq": info["freq"],
            "channel": info["channel"],
            "band": info["band"],
        }
        for mac, info in ap_ch.items()
        if mac in roles
    }
    channels = {"by_channel": by_channel, "ap_channels": ap_channels}

    return {
        "total_frames": n,
        "duration_sec": round(frames[-1].epoch - frames[0].epoch, 1),
        "time_start": frames[0].timestamp,
        "time_end": frames[-1].timestamp,
        "retry_count": retry_count,
        "retry_pct": round(retry_count * 100.0 / n, 2) if n else 0,
        "type_dist": dict(type_counts),
        "protocol_dist": dict(proto_counts.most_common(20)),
        "subtype_dist": dict(subtype_counts.most_common(20)),
        "devices": devices,
        "channels": channels,
    }


def _retry_per_sec(device_frames: List[Frame]) -> List[Dict[str, Any]]:
    """장치(ta)의 송신 프레임을 초 단위로 묶어 retry%를 집계한다.

    각 초의 {retry 프레임 수, 전체 프레임 수, retry_pct}를 epoch 오름차순으로 반환.
    rssi 유무와 무관하게 그 장치가 송신한 모든 프레임이 분모(total)에 들어간다
    (retry는 rssi 없는 프레임에도 set될 수 있으므로).
    """
    by_sec: Dict[int, Dict[str, int]] = defaultdict(lambda: {"retry": 0, "total": 0})
    for f in device_frames:
        # epoch 없는/비유한 프레임이 build 전체를 깨지 않도록 방어 —
        # _structured_per_second와 동일 (int(nan)→ValueError, PR #27 리뷰).
        if f.epoch is None or not math.isfinite(f.epoch):
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


def _bucket_rssi_timeline(tx_frames: List[Frame]) -> List[Dict[str, Any]]:
    """RSSI 샘플을 **1초 버킷**으로 집계한 시계열.

    프레임당 1항목(원샘플)으로 내보내면 2시간·143만 프레임 캡처에서 이 필드
    하나가 결과 JSON의 53MB를 차지했다. 프론트(timeline.js)는 어차피 장치당
    RSSI_SCATTER_MAX(800)점으로 솎아 그리므로 그 전송량의 대부분이 버려졌다.

    항목 스키마:
        {"epoch": 초(int), "rssi": 버킷 평균(소수1), "rssi_min", "rssi_max",
         "n": 샘플 수, "mcs": 버킷 최빈 MCS}

    `epoch`/`rssi` 키와 그 의미("그 시점의 대표 RSSI")를 구버전 원샘플 항목과
    똑같이 유지하는 게 핵심이다 — timeline.js, timeline_series.project_rssi_series,
    signal_cliff, evidence의 축 계산이 구버전 결과와 신버전 결과를 분기 없이
    그대로 읽는다 (메모리 serialized-result-backward-compat).

    `rssi_min`/`rssi_max`를 함께 남기는 이유는 signal_cliff가 '5초 내 10dB 하락'을
    판정할 때 버킷 평균만 보면 순간 급락을 놓치기 때문이다(그쪽 docstring 참조).

    손상 epoch(None/NaN/Inf)은 제외한다 — int() 예외 방어
    (_structured_per_second와 동일 원칙).
    """
    buckets: Dict[int, Dict[str, Any]] = {}
    for f in tx_frames:
        epoch = f.epoch
        if epoch is None or not math.isfinite(epoch):
            continue
        rssi = f.rssi_first
        if rssi is None:
            continue
        sec = int(epoch)
        b = buckets.get(sec)
        if b is None:
            b = buckets[sec] = {
                "sum": 0, "n": 0, "min": rssi, "max": rssi, "mcs": Counter(),
            }
        b["sum"] += rssi
        b["n"] += 1
        if rssi < b["min"]:
            b["min"] = rssi
        if rssi > b["max"]:
            b["max"] = rssi
        m = f.mcs_int
        if m is not None:
            b["mcs"][m] += 1

    timeline: List[Dict[str, Any]] = []
    for sec in sorted(buckets):
        b = buckets[sec]
        top_mcs = b["mcs"].most_common(1)
        timeline.append(
            {
                "epoch": sec,
                "rssi": round(b["sum"] / b["n"], 1),
                "rssi_min": b["min"],
                "rssi_max": b["max"],
                "n": b["n"],
                "mcs": top_mcs[0][0] if top_mcs else None,
            }
        )
    return timeline


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

        rssi_timeline = _bucket_rssi_timeline(tx_frames)
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


def _ping_ip_to_name(full_list: List[Dict[str, Any]]) -> Dict[str, str]:
    """full_list에서 IP→장치명 매핑을 학습.

    ping의 다수(역방향·seq-gap 추정손실)는 src/dst MAC이 비어 장치를 못 가른다.
    src/dst IP는 항상 있으므로, MAC(=장치명 문자열, 예 "STA1(aa)")이 있는 항목에서
    IP→장치명을 학습해 IP로 식별한다.
    """
    ip_to_name: Dict[str, str] = {}
    for p in full_list:
        if p.get("src") and p.get("src_mac"):
            ip_to_name[p["src"]] = p["src_mac"]
        if p.get("dst") and p.get("dst_mac"):
            ip_to_name[p["dst"]] = p["dst_mac"]
    return ip_to_name


def _ping_sta_of(p: Dict[str, Any], ip_to_name: Dict[str, str]) -> str:
    """ping 항목의 상대 장치(STA) 식별 — src/dst 중 STA로 매핑되는 IP의 장치명.

    STA 매핑 실패 시 AP가 아닌 IP를 STA 후보로(IP 그대로 표시), 끝내 없으면 '?'.
    → 반환 키에 IP/'?' 가 섞일 수 있다(전체 집계엔 포함, 장치명 hover에선 빠짐).
    """
    for ip in (p.get("dst"), p.get("src")):
        dev = ip_to_name.get(ip)
        if dev and dev.startswith("STA"):
            return dev
    for ip in (p.get("dst"), p.get("src")):
        if ip and not ip_to_name.get(ip, "").startswith("AP"):
            return ip
    return "?"


def _ping_loss_streaks(full_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """장치별 연속 Loss 구간 탐지 — 특정 장치가 연속으로 실패한 구간을 따로 낸다.

    full_list에서 status=loss/loss_gap 항목만 장치(_ping_sta_of)별로 모아, 각 장치
    내부에서 시간순으로 인접 loss 간격 <= LOSS_STREAK_GAP_SEC 로 이어지고 길이
    >= LOSS_STREAK_MIN_LEN 인 run을 하나의 구간으로 낸다. 전역 시간구간(ping_loss.py
    텍스트)과 달리 장치를 섞지 않아 "어느 장치가 언제부터 연속 실패했는지"를 준다.
    """
    ip_to_name = _ping_ip_to_name(full_list)
    by_dev: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in full_list:
        if p.get("status") not in ("loss", "loss_gap"):
            continue
        if not isinstance(p.get("epoch"), (int, float)):
            continue
        by_dev[_ping_sta_of(p, ip_to_name)].append(p)

    streaks: List[Dict[str, Any]] = []
    for dev, items in by_dev.items():
        items.sort(key=lambda x: x["epoch"])
        for s, e in find_time_streaks([x["epoch"] for x in items]):
            seg = items[s:e + 1]
            refs = [x["req_num"] for x in seg if x.get("req_num") is not None]
            streaks.append({
                "device": dev,
                "start_epoch": items[s]["epoch"],
                "end_epoch": items[e]["epoch"],
                "start_time": seg[0].get("req_time"),
                "end_time": seg[-1].get("req_time"),
                "count": e - s + 1,
                "duration_sec": round(items[e]["epoch"] - items[s]["epoch"], 1),
                "first_seq": seg[0].get("seq"),
                "last_seq": seg[-1].get("seq"),
                "frame_refs": refs[:20],
            })
    streaks.sort(key=lambda x: (x["start_epoch"], str(x["device"])))
    return streaks


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

    # 장치 식별은 _ping_ip_to_name/_ping_sta_of로 단일화 (장치별 streak 탐지와 동일 기준).
    ip_to_name = _ping_ip_to_name(full_list)

    def _sta_of(p: Dict[str, Any]) -> str:
        return _ping_sta_of(p, ip_to_name)

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
    ping["loss_streaks"] = _ping_loss_streaks(ping.get("full_list", []))
    # pairs/losses는 full_list와 **같은 entry 객체**를 담은 부분수열이라
    # (build_ping_matches의 lockstep 불변식) 파이썬 메모리에선 참조 공유로
    # 공짜지만, JSON에서는 full_list가 통째로 두 번 더 직렬화된다 — 2시간
    # 캡처 실측에서 structured.ping 32.8MB의 절반이 이 중복이었다. 결과에서
    # 빼고 소비자는 ping_pairs()/ping_losses()로 파생한다(status 필터가 곧
    # 원래 부분수열이라 lockstep은 구성상 성립). 구버전 result에는 두 키가
    # 남아 있고 헬퍼가 그때는 저장된 값을 그대로 쓴다 —
    # serialized-result-backward-compat.
    ping.pop("pairs", None)
    ping.pop("losses", None)
    return ping


def _structured_roaming(
    frames: List[Frame],
    roles: Dict[str, Dict[str, Any]],
    handshakes: Optional[List[Dict[str, Any]]] = None,
    ap_ch: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """roaming 이벤트를 구조화.

    handshakes(structured.eapol의 핸드셰이크 목록)가 주어지면 각 시퀀스에
    assoc 직후 첫 4-way duration(four_way_ms)을 부착한다(매칭 실패 시 None).
    """
    from ..core.detector import mac_name
    from ..core.modules.eapol import match_four_way

    roaming_frames = [f for f in frames if f.is_roaming_related]
    sta_macs = {mac for mac, role in roles.items() if role.get("role") == "STA"}
    # AP별 대표 채널(beacon 기준) — 이전/이후 AP의 채널·밴드 전환 판정용.
    if ap_ch is None:
        ap_ch = ap_channel_map(frames, roles)

    def _ch_of(mac: str, key: str) -> Optional[Any]:
        info = ap_ch.get(mac)
        return info.get(key) if info else None

    # 짝짓기 규칙은 roaming.pair_roaming_sequences(단일 소스) — 텍스트 모듈과
    # 같은 시퀀스를 봐야 한다. 이전에는 이 로직이 양쪽에 복제돼 있었고, 그래서
    # "앵커를 소비 후 지우지 않아 수십 초 전 Auth와 짝지어지는" 결함도 양쪽에
    # 똑같이 있었다(자세한 근거는 그 함수 docstring).
    from ..core.modules.roaming import (
        MISSING_FRAME_LABELS,
        classify_slow,
        pair_roaming_sequences,
        roam_total_ms,
    )

    sequences = []
    for pairing in pair_roaming_sequences(roaming_frames, sta_macs):
        frame = pairing.assoc
        auth_frame = pairing.auth
        # gap_ms는 **None일 수 있다**(이 로밍의 Auth가 캡처에 없어 시작 시각을
        # 모르는 경우). 시퀀스 자체는 남긴다 — 로밍은 실제로 일어났으므로 횟수에서
        # 빠지면 안 되고, 대신 gap을 지어내지 않는다(정직한 공백). 소비자는
        # gap_ms is None을 반드시 처리해야 한다.
        gap_ms = pairing.gap_ms
        prev_ap = frame.current_ap or ""
        prev_band = _ch_of(prev_ap, "band") if prev_ap else None
        new_band = _ch_of(frame.ra, "band")
        # 양쪽 밴드를 모두 알 때만 전환 여부 판정, 아니면 None(정보 없음).
        band_change = (
            prev_band != new_band
            if prev_band is not None and new_band is not None
            else None
        )
        # 4-way를 한 번만 매칭해 duration과 종료 시각을 함께 쓴다.
        hs = match_four_way(frame.epoch, frame.ta, handshakes or [], ap=frame.ra)
        four_way_ms = hs.get("duration_ms") if hs else None
        # 전체 소요와 사유는 roaming.roam_total_ms(단일 소스) — 텍스트 리포트와
        # 같은 식을 쓴다. 같은 계산이 두 곳에 있으면 한쪽만 고쳐져 갈라진다.
        total_roam_ms, total_note = roam_total_ms(
            auth_frame.epoch if auth_frame is not None else None, hs
        )
        # 판정 규칙은 roaming.classify_slow(단일 소스) — 텍스트 리포트와 화면이
        # 다른 느린 로밍 건수를 말하면 안 된다(이 버그의 근원이 로직 복제였다).
        is_slow, slow_basis = classify_slow(total_roam_ms, gap_ms)
        sequences.append(
            {
                "sta": frame.ta,
                "sta_name": mac_name(frame.ta, roles),
                "prev_ap": prev_ap,
                "prev_ap_name": mac_name(prev_ap, roles) if prev_ap else "",
                "ap": frame.ra,
                "ap_name": mac_name(frame.ra, roles),
                "auth_epoch": auth_frame.epoch if auth_frame else None,
                "assoc_epoch": frame.epoch,
                "auth_fnum": auth_frame.number if auth_frame else None,
                "assoc_fnum": frame.number,
                "gap_ms": round(gap_ms, 1) if gap_ms is not None else None,
                "assoc_type": frame.subtype_name,
                # 느린 로밍 판정은 **로밍 전체 소요(total_roam_ms)** 기준이다.
                # gap_ms(Auth→Reassoc)에만 임계를 걸면 전체 25.2ms 중 5.3ms
                # 구간만 보게 돼, 4-way가 길어 실제로 느린 로밍을 놓친다
                # (실측: gap 6.3ms인데 4-way 41.7ms로 전체 105ms인 건이 있다).
                #
                # total이 없어도(4-way 미포착) **total ≥ gap이 항상 성립**하므로
                # gap이 이미 임계를 넘으면 그 로밍은 확정적으로 느리다 — 아는
                # 정보를 버리지 않는다. 둘 다 아니면 판정 불가(slow_basis=None)로
                # 두고, 건강도 분모에서 제외한다.
                "is_slow": is_slow,
                "slow_basis": slow_basis,
                # gap을 무엇을 기준으로 쟀는지 / 무엇이 없어서 못 쟀는지.
                "gap_basis": pairing.basis,
                "missing": list(pairing.missing),
                "missing_labels": [
                    MISSING_FRAME_LABELS.get(code, code) for code in pairing.missing
                ],
                "gap_note": pairing.note,
                "prev_ap_channel": _ch_of(prev_ap, "channel") if prev_ap else None,
                "prev_ap_band": prev_band,
                "ap_channel": _ch_of(frame.ra, "channel"),
                "ap_band": new_band,
                "band_change": band_change,
                "four_way_ms": four_way_ms,
                # 로밍 **전체** 소요: Auth 요청 → 4-way 완료.
                # gap_ms(Auth→Reassoc 요청)는 전체의 일부에 불과하다 — 실측
                # 중앙값이 전체 25.1ms 중 5.3ms로, 나머지 대부분이 4-way다.
                # gap+four_way 단순 합이 아니라 실제 종료 시각에서 계산한다
                # (Reassoc 요청 ~ 4-way 시작 사이 대기가 빠지기 때문).
                "total_roam_ms": total_roam_ms,
                # 4-way를 못 찾으면 전체 소요를 알 수 없다(FT로 생략됐거나
                # 모니터가 EAPOL을 놓쳤거나) — 지어내지 않고 None.
                "total_basis": "four_way" if total_roam_ms is not None else None,
                "total_note": total_note,
            }
        )

    return {
        "roaming_frame_count": len(roaming_frames),
        "sequences": sequences,
    }


def _structured_per_second(frames: List[Frame]) -> Dict[str, Any]:
    """초당 프레임 수 시계열.

    손상 epoch(None/NaN/Inf) 프레임은 집계에서 제외하고, zero-fill 구간이
    _SNIFFER_FILL_MAX_SPAN_SEC를 넘으면 관측된 초만 담는 희소 timeline로
    폴백한다 — _structured_sniffer_compare와 동일 방어(PR #24 리뷰에서
    공통 이슈로 기록된 형제 함수 미러링, 백로그 ③).
    """
    sec_counts: "Counter[int]" = Counter()
    retry_counts: "Counter[int]" = Counter()
    byte_counts: "Counter[int]" = Counter()
    data_byte_counts: "Counter[int]" = Counter()
    for f in frames:
        if f.epoch is None or not math.isfinite(f.epoch):
            continue
        sec = int(f.epoch)
        sec_counts[sec] += 1
        if f.retry:
            retry_counts[sec] += 1
        # throughput용 바이트 집계 — bytes는 전체(frame.len 합), data_bytes는
        # Data 타입만. Mbps 환산은 소비자(프론트/리포트)가 ×8/1e6으로 수행.
        byte_counts[sec] += f.length
        if f.is_data:
            data_byte_counts[sec] += f.length
    if not sec_counts:
        return {"timeline": []}
    lo, hi = min(sec_counts), max(sec_counts)
    secs = range(lo, hi + 1) if hi - lo <= _SNIFFER_FILL_MAX_SPAN_SEC else sorted(sec_counts)
    timeline = [
        {
            "epoch": sec,
            "total": sec_counts.get(sec, 0),
            "retry": retry_counts.get(sec, 0),
            "bytes": byte_counts.get(sec, 0),
            "data_bytes": data_byte_counts.get(sec, 0),
        }
        for sec in secs
    ]
    return {"timeline": timeline}


def _device_entry_stats(dev_frames, is_tx, mac: str, role: str) -> Dict[str, Any]:
    """단일 장치(또는 전체 시스템)의 프레임 통계 entry를 만든다.

    is_tx(f) = 그 프레임이 이 주체의 '송신'인지 판별. 장치는 f.ta == mac, 전체
    시스템은 f.ta가 존재하는 모든 프레임(송신자 있는 프레임)을 송신으로 본다.
    장치별/전체가 동일 로직·동일 구조를 공유하도록 한 곳에 모은다.
    """
    from ..core.models import SUBTYPE_NAMES

    type_dist = Counter(f.frame_type for f in dev_frames)
    subtype_dist = Counter(f.subtype for f in dev_frames)
    retry_count = sum(1 for f in dev_frames if f.retry)

    subtype_named = {}
    for st, cnt in subtype_dist.most_common(20):
        name = SUBTYPE_NAMES.get(st, f"type={st}")
        subtype_named[name] = cnt

    tx_frames = [f for f in dev_frames if is_tx(f)]
    mcs_dist = Counter(f.mcs_int for f in tx_frames if f.mcs_int is not None)
    mcs_named = {str(k): v for k, v in sorted(mcs_dist.items())}

    # PHY 모드별 분리 + MCS별 retry 집계. HT/VHT/HE/EHT는 MCS index, Legacy는 Mbps rate.
    # 한 주체가 mode를 섞어 송신하는 경우(예: HE 데이터 + 6Mbps mgmt)도 정직하게 표현.
    phy_buckets: Dict[str, "Counter[str]"] = {
        "HT": Counter(), "VHT": Counter(), "HE": Counter(),
        "EHT": Counter(), "Legacy": Counter(),
    }
    phy_retry: Dict[str, "Counter[str]"] = {
        "HT": Counter(), "VHT": Counter(), "HE": Counter(),
        "EHT": Counter(), "Legacy": Counter(),
    }
    phy_frame_count: "Counter[str]" = Counter()
    for f in tx_frames:
        phy = getattr(f, "mcs_phy", "") or ""
        if phy in ("HT", "VHT", "HE", "EHT"):
            m = f.mcs_int
            if m is None:
                continue
            key = str(m)
        else:
            phy = "Legacy"
            key = (getattr(f, "data_rate", "") or "").split(",")[0].strip()
            if not key:
                continue
        phy_buckets[phy][key] += 1
        phy_frame_count[phy] += 1
        if f.retry:
            phy_retry[phy][key] += 1
    mcs_by_phy = {
        phy: dict(sorted(c.items(), key=lambda kv: float(kv[0])))
        for phy, c in phy_buckets.items() if c
    }
    # MCS별 retry: 각 PHY+MCS의 {total, retry, retry_pct} (mcs_by_phy와 동일 키 구조).
    mcs_retry_by_phy = {
        phy: {
            k: {
                "total": phy_buckets[phy][k],
                "retry": phy_retry[phy][k],
                "retry_pct": round(phy_retry[phy][k] * 100 / phy_buckets[phy][k], 1)
                if phy_buckets[phy][k] else 0,
            }
            for k in sorted(phy_buckets[phy], key=lambda x: float(x))
        }
        for phy in phy_buckets if phy_buckets[phy]
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
    # 손상 epoch(None/NaN/Inf) 프레임은 버킷 계산에서 제외 — int() 예외와 비교
    # TypeError 방어. span이 상한을 넘으면(먼 미래 epoch 등) 버킷 통계 자체를
    # 생략한다(정직한 공백) — 버킷 수 자체가 폭발하는 경로 차단
    # (_SNIFFER_FILL_MAX_SPAN_SEC 동일 원칙, PR #27 리뷰).
    finite_frames = [
        f for f in dev_frames if f.epoch is not None and math.isfinite(f.epoch)
    ]
    # 경계는 위치([0]/[-1])가 아니라 min/max — dev_frames의 epoch 정렬 가정에
    # 기대지 않는다 (PR #27 리뷰 4R; 정렬 입력에선 동일값이라 동작 불변).
    _lo = min((f.epoch for f in finite_frames), default=None)
    _hi = max((f.epoch for f in finite_frames), default=None)
    if finite_frames and int(_hi) - int(_lo) <= _SNIFFER_FILL_MAX_SPAN_SEC:
        start_epoch = int(_lo)
        end_epoch = int(_hi)
        bucket_size = 10  # 10초 구간
        bucket_count = (end_epoch - start_epoch) // bucket_size + 1
        # 버킷별 집계를 **단일 패스**로 채운다 (백로그 ⑥). 이전 구현은 버킷마다
        # finite_frames를 통째로 재스캔해 O(span/10 × frames)였다 — 2시간
        # (719버킷)·143만 프레임 실측에서 장치별+전체 통계에만 315초가 들었다.
        # 프레임마다 자기 버킷 인덱스를 한 번 계산해 누적하면 O(frames + 버킷수)로
        # 같은 결과를 낸다. 누적 순서가 프레임 순서 그대로라 Counter 삽입 순서도
        # 보존되어 most_common(5)의 동점 순서까지 이전과 동일하다.
        agg: List[Optional[Dict[str, Any]]] = [None] * bucket_count
        for f in finite_frames:
            bi = int((f.epoch - start_epoch) // bucket_size)
            if bi < 0 or bi >= bucket_count:
                # 구 루프의 `bucket_start <= f.epoch < bucket_end`도 범위 밖
                # 프레임(음수 epoch 등 int() 절삭 경계)은 어느 버킷에도 넣지
                # 않았다 — 그 동작을 그대로 유지한다.
                continue
            b = agg[bi]
            if b is None:
                b = agg[bi] = {
                    "total": 0, "retry": 0, "tx_total": 0,
                    "phy_mcs": Counter(), "legacy": Counter(),
                    "phy_mode": Counter(), "mcs_sum": 0, "mcs_n": 0,
                }
            b["total"] += 1
            if f.retry:
                b["retry"] += 1
            # bucket별 MCS / PHY 통계 (송신 프레임 기준)
            if not is_tx(f):
                continue
            b["tx_total"] += 1
            phy = getattr(f, "mcs_phy", "") or ""
            if phy in ("HT", "VHT", "HE", "EHT"):
                m = f.mcs_int
                if m is not None:
                    b["phy_mcs"][f"{phy} MCS{m}"] += 1
                    b["phy_mode"][phy] += 1
                    b["mcs_sum"] += m
                    b["mcs_n"] += 1
            else:
                rate = (getattr(f, "data_rate", "") or "").split(",")[0].strip()
                if rate:
                    b["legacy"][f"Legacy {rate}Mbps"] += 1
                    b["phy_mode"]["Legacy"] += 1

        for bi in range(bucket_count):
            bucket_start = start_epoch + bi * bucket_size
            b = agg[bi]
            if b is None:
                # 관측 프레임이 없는 구간 — 구 루프의 빈 버킷 출력과 동일.
                per_bucket.append(
                    {
                        "epoch": bucket_start,
                        "total": 0,
                        "retry": 0,
                        "retry_pct": 0,
                        "mcs_breakdown": "",
                        "avg_mcs": None,
                        "legacy_pct": 0,
                        "tx_total": 0,
                        "phy_mode_dist": {},
                    }
                )
                continue
            total = b["total"]
            retries = b["retry"]
            combined = b["phy_mcs"] + b["legacy"]
            mcs_breakdown = ", ".join(
                f"{k}×{v:,}" for k, v in combined.most_common(5)
            )
            mcs_n = b["mcs_n"]
            avg_mcs = round(b["mcs_sum"] / mcs_n, 1) if mcs_n else None
            tx_total = b["tx_total"]
            legacy_n = sum(b["legacy"].values())
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
                    "phy_mode_dist": dict(b["phy_mode"]),
                }
            )

        # retry 피크 구간 zoom-in (top 3 retry%, total>50인 bucket)
        candidate_peaks = sorted(
            [b for b in per_bucket if b.get("total", 0) > 50],
            key=lambda b: -b.get("retry_pct", 0),
        )[:3]
        for pk in candidate_peaks:
            if pk.get("retry_pct", 0) < 10:
                break
            pk_start = pk["epoch"]
            pk_end = pk_start + bucket_size
            # finite_frames 재사용 — 원본 dev_frames를 다시 스캔하면 손상
            # epoch(None 비교 TypeError)이 peak 경로에서 되살아난다 (PR #27 Codex).
            pk_frames = [
                f for f in finite_frames if pk_start <= f.epoch < pk_end
            ]
            sub_buckets = []
            for sub_start in range(pk_start, pk_end):
                sub_end = sub_start + 1
                sub = [f for f in pk_frames if sub_start <= f.epoch < sub_end]
                if not sub:
                    continue
                sub_total = len(sub)
                sub_retry = sum(1 for f in sub if f.retry)
                sub_tx = [f for f in sub if is_tx(f)]
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

    return {
        "mac": mac,
        "role": role,
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
        "mcs_retry_by_phy": mcs_retry_by_phy,
        "phy_summary": phy_summary,
        "rssi_stats": rssi_stats,
        "per_bucket": per_bucket if dev_frames else [],
        "retry_peaks": retry_peaks if dev_frames else [],
    }


def _structured_device_stats(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index
) -> Dict[str, Any]:
    """장치별 프레임 타입/서브타입/MCS/RSSI/시간대별 통계."""
    result = {}
    for mac, info in roles.items():
        if index:
            dev_frames = index.by_ta.get(mac, []) + index.by_ra.get(mac, [])
        else:
            dev_frames = [f for f in frames if f.ta == mac or f.ra == mac]
        if not dev_frames:
            continue
        result[info["name"]] = _device_entry_stats(
            dev_frames, lambda f, m=mac: f.ta == m, mac, info["role"]
        )
    return result


def _structured_system_stats(frames: List[Frame], index) -> Dict[str, Any]:
    """네트워크 전체(모든 송신 프레임) 통계 — 장치별과 동일 구조의 단일 entry.

    전체 시스템을 하나의 가상 장치처럼 보고, 송신은 f.ta가 존재하는 모든 프레임으로
    집계한다(특정 장치가 아니라 캡처 전체의 MCS/retry 분포). frames는 시간순 정렬
    가정(pipeline에서 정렬됨).
    """
    if not frames:
        return {}
    return _device_entry_stats(frames, lambda f: bool(f.ta), "", "SYSTEM")


#: 유선 손실 구간 대조 창 (streak 앞뒤 초) — 로밍·재전송이 손실보다 약간 앞설 수 있다
_WIRED_LOSS_WINDOW_SEC = 2.0
#: 대조하는 streak 수 상한 — 이슈 목록 폭주 방지
_WIRED_LOSS_MAX_STREAKS = 20
#: 재전송 "폭주"로 인정하는 최소 건수/비율 — 이 둘을 모두 넘겨야 이상 징후로 본다.
#: 낱개 retry는 정상 동작이라 이상 징후에 포함하지 않는다.
_WIRED_LOSS_RETRY_MIN = 3
_WIRED_LOSS_RETRY_PCT = 30.0


def _cliffs_overlapping_window(signal_cliffs, win, allow_names=None):
    """cliff 중 시간 구간이 손실 창과 겹치는 것들. [(sta_name, cliff), ...].

    allow_names가 주어지면 그 STA 이름들의 cliff만 본다 — 대상 STA가 특정된
    경우 무관한 STA의 절벽이 이 STA의 유선 손실을 이상 징후로 둔갑시키면 안 된다.
    None이면(매핑 실패) 전체 STA를 본다.

    signal_cliffs는 직렬화 라운드트립에서 null이거나 dict가 아닌 항목을 포함할 수
    있다(구버전 result 호환) — sta_diags의 기존 방어 패턴과 동일하게 isinstance로 거른다.
    cliff는 {epoch, duration_sec, drop_db, ...}(analyzer/web/signal_cliff.py) — 프레임
    참조가 없어 [epoch, epoch+duration_sec] 구간으로 겹침을 판정한다.
    """
    out = []
    if not isinstance(signal_cliffs, dict):
        return out
    for sta_name, sc in signal_cliffs.items():
        if allow_names is not None and sta_name not in allow_names:
            continue
        if not isinstance(sc, dict):
            continue
        for c in sc.get("cliffs") or []:
            if not isinstance(c, dict):
                continue
            c_start = c.get("epoch")
            if not isinstance(c_start, (int, float)):
                continue
            dur = c.get("duration_sec")
            c_end = c_start + dur if isinstance(dur, (int, float)) else c_start
            if c_start <= win["end_epoch"] and c_end >= win["start_epoch"]:
                out.append((sta_name, c))
    return out


def _cliff_sta_names(signal_stas, sta_macs):
    """signal["stas"]의 이름→mac 매핑으로 sta_macs에 해당하는 STA 이름 집합.

    signal_cliffs의 키는 STA 표시명(roles[mac]["name"])이라 MAC과 직접 비교할 수
    없다. structured["signal"]["stas"][name]["mac"]이 그 역참조를 제공한다.
    """
    names = set()
    if not isinstance(signal_stas, dict):
        return names
    for name, info in signal_stas.items():
        if isinstance(info, dict) and info.get("mac") in sta_macs:
            names.add(name)
    return names


def _cliff_frame_refs(cliffs, signal_stas, frames, index):
    """cliff 근거 프레임 — evidence.cliff_evidence를 STA별로 재사용해 소싱.

    "창 안 아무 프레임"을 근거로 대면 "이 구간에 RSSI 절벽이 있었다"는 결론과
    프레임 사이에 인과가 없다. cliff 시각 ±1초의 그 STA 송신 프레임을 근거로
    삼는 기존 헬퍼(sta_diags의 signal_cliff issue와 동일)를 그대로 쓴다.
    """
    from . import evidence as ev

    by_mac = defaultdict(list)
    for sta_name, c in cliffs:
        info = signal_stas.get(sta_name) if isinstance(signal_stas, dict) else None
        mac = info.get("mac") if isinstance(info, dict) else None
        if mac:
            by_mac[mac].append(c)
    refs = []
    for mac, mac_cliffs in by_mac.items():
        nums, _win = ev.cliff_evidence(mac, mac_cliffs, frames, index)
        refs.extend(nums)
    return refs


def _frame_is_ap(mac, frame, ap_macs):
    """이 프레임에서 그 MAC이 AP인가 — detected roles 또는 프레임의 BSSID로 판정.

    인프라 모드에서 BSSID는 AP의 MAC이다: TA==BSSID면 AP가 송신한 프레임,
    RA==BSSID면 AP가 수신한 프레임. beacon/ProbeResp/AssocResp가 없어
    detect_roles가 AP를 못 찾은 data-only 캡처에서도 이 판정은 성립하므로,
    ap_macs만 보는 것보다 훨씬 넓은 캡처에서 AP를 가려낼 수 있다.

    BSSID가 비면(필드 없음/파싱 실패) 그 프레임에 대해서는 판정 근거가 없어
    False — 호출부가 기존 방향 휴리스틱으로 떨어진다. IBSS/ad-hoc은 BSSID가 어느
    단말의 MAC도 아니므로 자연히 False가 되어 영향이 없다.
    """
    if not mac:
        return False
    return mac in ap_macs or (bool(frame.bssid) and mac == frame.bssid)


def _sender_sta_macs_by_target(frames, sender, ap_macs=None, targets=None):
    """ping **대상 IP별** 무선 상대 STA MAC 집합. {target_ip: {mac, ...}}.

    streak마다 그 streak의 target 매핑만 써야 한다 — sender가 여러 STA를 ping하는
    캡처에서 전체 target의 매핑을 합쳐 쓰면(union) target B STA의 로밍/재전송
    폭주/RSSI 절벽이 target A의 손실 구간을 설명하는 근거로 둔갑한다.

    앵커로 쓰는 프레임은 **그 GT가 집계한 ping 모집단**(sender↔targets의 ICMP echo
    request/reply)으로 한정한다. sender IP가 실린 아무 패킷이나 앵커로 쓰면, 같은
    호스트가 무관한 STA로 보내는 TCP/UDP 트래픽까지 매핑에 섞여 그 STA의
    로밍·재전송 폭주·RSSI 절벽이 대상 STA의 유선 손실을 high로 둔갑시킨다.
    targets(gt['targets'] 키)가 없으면(구버전 결과 등) sender 기준 ICMP echo만으로
    매핑한다 — 대상 목록이 없다는 이유로 매핑을 포기하진 않는다.

    앵커 프레임에서 그 IP의 **무선 상대편**을 역추적한다. 어느 쪽이 상대인지는
    토폴로지에 따라 다르다:

    - sender가 STA 자신인 배치: 업링크 요청은 STA가 직접 송신하므로
      ip.src==sender 프레임의 TA가 STA, 응답은 STA로 돌아오므로 ip.dst==sender
      프레임의 RA가 STA.
    - sender가 AP **상류**인 배치(유선 EXPING PC가 AP 너머의 STA들을 ping —
      이 도구의 주 용도): 다운링크 요청은 AP가 송신하므로 ip.src==sender 프레임의
      TA는 AP고 상대 STA는 RA, 업링크 응답은 ra=AP이므로 상대 STA는 TA다.

    두 배치를 가르는 근거는 "프레임의 한쪽이 AP인가"다 — AP면 반대편이 그 sender의
    무선 상대다. AP를 STA로 잘못 매핑하면 그 AP를 경유하는 모든 무선 트래픽이
    스코프에 들어와(AP는 모든 STA의 상대다) 스코프가 통째로 무력화된다. 판정은
    `_frame_is_ap`가 detected roles(ap_macs)와 **프레임의 BSSID** 둘 다로 한다 —
    beacon/ProbeResp/AssocResp가 없는 data-only 캡처는 detect_roles가 AP를 하나도
    못 찾지만, 인프라 모드의 BSSID는 AP의 MAC이라 프레임만으로도 판정된다.
    한계: ap_macs가 비고 BSSID도 없는 프레임은 판정 근거가 전무해 기존 방향
    휴리스틱(요청의 TA / 응답의 RA)으로 떨어진다 — sender가 STA 자신인 배치에서만
    맞고, 상류 배치라면 그 프레임에서는 AP가 매핑될 수 있다.

    브로드캐스트/멀티캐스트는 제외(_is_unicast). 어떤 target의 앵커도 못 찾으면 그
    키는 아예 없다 — 호출부가 그 streak만 "매핑 실패"로 처리해 전체-무선 대조로
    폴백한다. sender가 STA 자신인 배치에서는 모든 target이 같은 MAC(그 STA의
    라디오)으로 매핑되는데, 실제로 같은 라디오이므로 정상이다.
    """
    by_target: Dict[str, set] = defaultdict(set)
    if not sender:
        return {}
    from ..core.detector import _is_unicast

    ap_macs = ap_macs or set()
    # targets: gt["targets"]는 {대상IP: {...}} — 키만 쓴다. 구버전/오염 값(None,
    # 문자열 등)은 빈 집합으로 정규화해 "대상 제한 없음"으로 떨어뜨린다.
    target_ips = set(targets) if isinstance(targets, (dict, list, set, tuple)) else set()
    for f in frames:
        if f.is_icmp_request and f.ip_src == sender:
            # echo request(sender → 대상). 송신자가 AP면 다운링크 — 상대는 RA.
            target, peer = f.ip_dst, (f.ra if _frame_is_ap(f.ta, f, ap_macs) else f.ta)
        elif f.is_icmp_reply and f.ip_dst == sender:
            # echo reply(대상 → sender). 수신자가 AP면 업링크 — 상대는 TA.
            target, peer = f.ip_src, (f.ta if _frame_is_ap(f.ra, f, ap_macs) else f.ra)
        else:
            continue
        if target_ips and target not in target_ips:
            continue
        # 고른 상대까지 AP면(DS 간 전달 등) 그 프레임은 앵커 기여 없음 — 잘못된
        # 매핑보다 무매핑이 낫다(호출부가 매핑 실패로 폴백한다).
        if target and _is_unicast(peer) and not _frame_is_ap(peer, f, ap_macs):
            by_target[target].add(peer)
    return dict(by_target)


#: 손실 판정의 근거 — 어느 관측을 썼는지. summary/report/AI가 함께 읽는다.
LOSS_BASIS_WIRED = "wired_gt"          # 유선 확정(1차)
LOSS_BASIS_WIRELESS = "wireless_observed"   # 무선 관측(유선 없을 때만)
LOSS_BASIS_LABELS = {
    LOSS_BASIS_WIRED: "유선 확정",
    LOSS_BASIS_WIRELESS: "무선 관측",
}


def _loss_for_judgment(ping, wireless_loss_pct, ping_available):
    """손실 판정에 쓸 `(loss_pct, basis)`. 판정 불가면 `(None, None)`.

    유선 ground truth가 **쓸 수 있는 상태**면 그 값을 쓴다. 세 가지를 확인한다.

    1. `error`가 없을 것.
    2. `extraction_partial`이 아닐 것 — tshark가 일부 행만 내고 비정상 종료하면
       (잘린/손상 pcap) `error` 없이 **과소 계상된** 손실률이 나온다. 못 읽은
       요청은 애초에 모집단에 없기 때문이다. 그걸 1차 판정으로 승격하면 건강도가
       부풀고 진짜 손실 이슈가 눌린다 — 이 PR이 막으려는 바로 그 실패(관측 한계를
       사실로 오인)를 반대 방향으로 반복하는 셈이다.
    3. 모집단(`total`)이 1건 이상일 것 — `total == 0`이면 시간창·IP 필터를 거친 뒤
       남은 교환이 없다는 뜻이라 손실률 0.0이 "손실 없음"이 아니라 **근거 없는 0**
       이다(그대로 쓰면 필터를 좁힐수록 건강해지는 역전).

    구버전 result에는 `ground_truth` 자체가 없으므로 자동으로 무선 경로를 탄다.
    `extraction_partial` 키가 없는 구버전 GT는 판정에 쓴다 — 그때의 무결성은
    소급해서 알 수 없고, 없는 정보를 이유로 기존 동작을 바꾸지는 않는다.
    """
    gt = ping.get("ground_truth")
    if isinstance(gt, dict) and "error" not in gt and not gt.get("extraction_partial"):
        total = gt.get("total")
        gt_pct = gt.get("loss_pct")
        # total은 int로 오지만(len(exchanges) → JSON), 방어적으로 수치면 받는다 —
        # 조용한 폴백은 원인을 추적하기 어렵다. bool은 int의 서브클래스라 True가
        # 1로 통과하므로 명시적으로 배제한다(손실률이 True인 GT는 GT가 아니다).
        if (
            isinstance(total, (int, float)) and not isinstance(total, bool) and total > 0
            and isinstance(gt_pct, (int, float)) and not isinstance(gt_pct, bool)
        ):
            return gt_pct, LOSS_BASIS_WIRED
    # 무선 폴백도 **값이 실제 수치일 때만** 근거를 주장한다.
    # `ping_stats.get("loss_pct", 0)`은 키가 있고 값이 None이면 0이 아니라 None을
    # 준다 — 이 저장소가 두 번 당한 함정이다(delay_analysis의 auth_epoch, prompts의
    # 정렬 키). 그대로 두면 `loss_pct_used=None`인데 `loss_basis="wireless_observed"`
    # 인 모순 상태가 리포트·AI로 흘러간다("무선으로 판정했는데 값은 없음").
    if ping_available and isinstance(wireless_loss_pct, (int, float)) \
            and not isinstance(wireless_loss_pct, bool):
        return wireless_loss_pct, LOSS_BASIS_WIRELESS
    return None, None


#: 로밍 관측 커버리지 — pcap이 본 구간이 STA 체감 로밍의 몇 %인가.
#: 실측(2시간 캡처, 776건 대조)은 pcap 25.1ms vs STA 체감 97.0ms로 **25.9%**다.
#: 나머지 74.1%(스캔·로밍 판단·드라이버 처리·키 설치)는 전파에 나타나지 않아
#: 모니터 캡처로는 원리적으로 볼 수 없다.
#:
#: 이건 **판정 임계가 아니라 해석 경고의 임계**다. 커버리지가 낮다는 건 네트워크가
#: 나쁘다는 뜻이 아니라 "캡처만으로는 로밍 체감을 말할 수 없다"는 뜻이다 —
#: 그래서 severity가 아니라 category로 구분하고 건강도에는 넣지 않는다.
ROAM_COVERAGE_MIN_PAIRS = 3     # 대조 표본이 이 미만이면 커버리지를 주장하지 않는다
#: 경고 조건은 `< ROAM_COVERAGE_LOW_PCT` — **경계값 50.0%는 경고를 내지 않는다**
#: (`test_threshold_boundary_is_not_low`가 고정). thresholds.py의 "경계값은 낮은
#: 단계에 포함" 규약과 같은 방향이다.
ROAM_COVERAGE_LOW_PCT = 50.0


def coverage_is_reportable(matched, visible_pct) -> bool:
    """커버리지를 **문장으로 단정해도 되는가** — 진단·리포트·화면의 단일 규칙.

    표본이 `ROAM_COVERAGE_MIN_PAIRS` 미만이면 "pcap이 보는 건 전체의 X%"라고
    말하지 않는다. 대조 1~2건으로 낸 비율은 중앙값이라 부르기도 민망하다.

    이 술어가 필요한 이유는 실제로 당했기 때문이다(PR #31 Codex P2): 진단 이슈는
    임계를 걸었는데 리포트(`> 0`)와 화면(`> 0`)이 각자 판단해, **같은 데이터에서
    진단은 "주장 안 함"인데 리포트는 "26%"라고 단정**했다. 규칙을 세 곳에 복제하면
    이렇게 갈라진다 — 이 저장소가 반복해서 당한 실패 모드다.

    화면은 파이썬을 부를 수 없으므로 결과를 `summary.roaming_coverage_reportable`로
    실어 보낸다(구버전 result엔 그 키가 없어 화면이 자체 폴백을 탄다).
    """
    return (
        isinstance(matched, int) and not isinstance(matched, bool)
        and matched >= ROAM_COVERAGE_MIN_PAIRS
        and isinstance(visible_pct, (int, float))
        and not isinstance(visible_pct, bool)
    )


def _median_ms(values) -> Optional[float]:
    """수치 중앙값(소수 1자리). 빈 입력이면 None — 0으로 뭉개지 않는다.

    `pipeline._p50`과 같은 정의(표준 중앙값, 짝수면 두 중앙값의 평균)를 쓴다.
    같은 화면에 나란히 놓이는 `station_logs.total_ms_p50`이 그 함수 산출이라,
    정의가 갈라지면 두 수치가 미묘하게 어긋난다. pipeline은 web.structured를
    import하므로 역방향 재사용은 순환이라 표준 라이브러리로 정의를 맞춘다.

    타입 필터는 **방어적 가드**다 — 현재 유일한 호출부(`_roam_coverage`)가 이미
    float만 담아 넘기므로 실행되지 않는다. 다른 호출부가 생겼을 때 `median`이
    문자열에 TypeError를 내거나 bool을 1ms로 세는 것을 막으려 남겨 둔다.
    """
    vals = [
        float(v) for v in values
        if isinstance(v, (int, float)) and not isinstance(v, bool)
    ]
    return round(median(vals), 1) if vals else None


def _roam_coverage(roam_seqs):
    """pcap이 본 로밍 구간의 비중 — `(matched, sta_p50, pcap_p50, visible_pct)`.

    분모는 **STA 체감(`sta_log.total_ms`)과 pcap 전체 소요(`total_roam_ms`)를 둘 다
    가진 시퀀스**다. 한쪽만 있는 건 대조가 성립하지 않으므로 세지 않는다 — 로그가
    안 붙은 로밍을 분모에 넣으면 "pcap이 더 많이 본다"는 반대 방향 왜곡이 된다.

    비율은 **두 중앙값의 비**다(시퀀스별 비율의 중앙값이 아니다). 화면
    `charts.js`의 STA 로그 카드가 쓰는 정의와 같아야 같은 수치를 말한다.

    대조 가능한 시퀀스가 없으면 `(0, None, None, None)` — 0%가 아니다. 0%는
    "전부 못 봤다"는 주장이고, 여기서 참인 건 "모른다"뿐이다.
    """
    pairs = []
    for s in roam_seqs or []:
        if not isinstance(s, dict):
            continue
        log = s.get("sta_log")
        if not isinstance(log, dict):
            continue
        sta_total, pcap_total = log.get("total_ms"), s.get("total_roam_ms")
        # bool은 int의 서브클래스라 True가 1ms로 통과한다(GT 판정과 같은 가드).
        if (
            isinstance(sta_total, (int, float)) and not isinstance(sta_total, bool)
            and isinstance(pcap_total, (int, float))
            and not isinstance(pcap_total, bool)
        ):
            pairs.append((float(sta_total), float(pcap_total)))
    if not pairs:
        return 0, None, None, None
    sta_p50 = _median_ms([p[0] for p in pairs])
    pcap_p50 = _median_ms([p[1] for p in pairs])
    # 체감 중앙값이 0이면 비율이 무한대가 된다. 로그 스탬프가 ms 단위라 극단적으로
    # 짧은 로밍에서 0이 나올 수 있다 — 지어내지 않고 측정 불가로 둔다.
    visible = round(pcap_p50 / sta_p50 * 100, 1) if sta_p50 else None
    return len(pairs), sta_p50, pcap_p50, visible


def _ground_truth_issue_candidates(gt, frames, signal_cliffs=None, signal_stas=None,
                                   index=None, ap_macs=None):
    """유선 확정 손실 streak별 무선 대조 이슈 후보. 근거 프레임이 없으면 후보 제외.

    로밍/재전송/RSSI 절벽 판정은 **그 streak의 target에 대응하는 STA**로 스코프를
    좁힌다(_sender_sta_macs_by_target) — 그러지 않으면 다중 STA 캡처에서 무관한
    STA나 다른 target STA의 이벤트가 이 손실을 설명하는 근거로 둔갑한다. 매핑
    앵커는 GT가 집계한 ping 모집단(sender↔gt['targets']의 ICMP echo)으로 한정되고
    (sender의 비-ICMP 트래픽이 무관한 STA를 끌어들이지 못하게), ap_macs(detected
    roles의 AP MAC)로 AP를 배제한다 — sender가 AP 상류면 sender IP가 걸린 프레임의
    상대가 AP라 AP를 매핑하게 되고, 그러면 그 AP를 경유하는 전체 무선이 스코프에
    들어와 스코프가 무력화된다. cliff는 signal_cliffs의 키가 STA 표시명이라
    signal_stas(=structured["signal"]["stas"], name→mac)로 역참조해 그 streak의 STA
    것만 인정한다. 매핑 실패(그 target의 ping이 무선에 안 잡힘, 암호화 미해제 등)
    시 **그 streak만** 전체-무선 대조로 폴백하되 귀속이 불확실하므로 severity를
    high→medium으로 낮추고 msg에 명시한다.

    이상 징후 = 로밍/해제 프레임 ≥1 또는 재전송 폭주(_WIRED_LOSS_RETRY_MIN건 이상 &&
    _WIRED_LOSS_RETRY_PCT% 이상) 또는 창과 겹치는 signal_cliff ≥1 (스펙 §4).
    낱개 retry(폭주 미달)만으로는 이상 징후로 보지 않는다 — 정상 동작 범위.

    frame_refs는 무선 pcap의 frame.number다 — 유선 프레임 번호를 섞으면 프레임
    테이블 조회가 깨진다. 캡처 구멍(창 안에 무선 프레임 0건)은 근거를 댈 수
    없어 이슈를 만들지 않는다(근거 없는 결론 금지) — 알려진 한계.
    """
    signal_cliffs = signal_cliffs if isinstance(signal_cliffs, dict) else {}
    signal_stas = signal_stas if isinstance(signal_stas, dict) else {}
    mapping = _sender_sta_macs_by_target(
        frames, gt.get("sender") or "", ap_macs, gt.get("targets")
    )
    # target별 sta_bssids(그 STA가 관측된 BSSID) — **전체 frames**에서 한 번씩만
    # 계산해 재사용한다(PR #22 14라운드 — Codex P1). STA의 소속 AP는 손실 창과
    # 무관한 전역 속성이라, in_win(그 streak의 창)으로 제한하면 창 안에 이 STA의
    # 트래픽이 우연히 없을 때(사용자 활동이 뜸한 순간) sta_bssids가 비어 버린다
    # — 전체 캡처에는 이 STA가 어느 AP에 붙어 있었는지 보여주는 프레임이 있을
    # 수 있는데도 그 정보를 못 쓰게 된다. 같은 target이 여러 streak를 가질 수
    # 있어(반복 손실 구간) target별로 한 번만 계산해 streak마다 전체 frames를
    # 다시 스캔하지 않는다.
    bssids_by_target = {
        target: {g.bssid for g in frames
                 if (g.ta in sta_macs or g.ra in sta_macs) and g.bssid}
        for target, sta_macs in mapping.items()
    }

    out = []
    for streak in (gt.get("streaks") or [])[:_WIRED_LOSS_MAX_STREAKS]:
        start, end = streak.get("start_epoch"), streak.get("end_epoch")
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            continue
        # 이 streak의 target STA만 — 다른 target STA의 이벤트는 이 손실의 근거가 아니다.
        sta_macs = mapping.get(streak.get("target")) or set()
        mapped = bool(sta_macs)
        sta_label = (
            f"STA {', '.join(sorted(sta_macs))}" if mapped
            else "STA 매핑 불가 — 전체 무선 기준"
        )
        # 매핑 성공 시 그 STA의 cliff만, 실패 시 None(전체 STA)으로 폴백.
        cliff_names = _cliff_sta_names(signal_stas, sta_macs) if mapped else None
        win = {"start_epoch": start - _WIRED_LOSS_WINDOW_SEC,
               "end_epoch": end + _WIRED_LOSS_WINDOW_SEC}
        in_win = [f for f in frames if win["start_epoch"] <= f.epoch <= win["end_epoch"]]
        if not in_win:
            continue
        # 매핑 성공 시 대상 STA의 프레임만, 실패 시 기존처럼 창 안 전체.
        scoped = (
            [f for f in in_win if f.ta in sta_macs or f.ra in sta_macs]
            if mapped else in_win
        )
        if mapped:
            # AP가 그 STA로 보내는 **브로드캐스트** Deauth/Disassoc(ta=AP,
            # ra=브로드캐스트)는 위 STA-MAC 술어(ta/ra ∈ sta_macs)에 걸리지 않는다
            # — ra가 브로드캐스트라 sta_macs 어디에도 없기 때문이다. 그 STA에 실제로
            # 영향을 미치는 방송 해제인데도 스코프에서 빠지면 창 안에 다른 이벤트가
            # 없을 때 "무선 이상 징후 없음"으로 오판된다(PR #22 12라운드 — Codex P1).
            # sta_bssids(전체 frames 기준, 위에서 target별로 사전 계산 — 14라운드)로
            # AP가 여럿인 캡처(로밍 등)에서 이 STA의 AP만 특정해 무관 AP의 방송
            # 해제를 배제한다. sta_bssids가 비면(이 STA가 전체 캡처에서도 BSSID와
            # 함께 한 번도 관측되지 않음) 그 STA의 AP를 특정할 근거가 전무하다 —
            # 12라운드의 _frame_is_ap 폴백(아무 AP나 수용)은 폐기했다. 근거 없이
            # 아무 AP를 그 STA의 AP로 추정하면 다중 AP 캡처에서 무관 AP의 방송
            # 해제가 이 STA의 손실 근거로 오귀속된다 — "무매핑이 오매핑보다
            # 낫다"는 9라운드 원칙과 같다.
            from ..core.detector import BROADCAST
            sta_bssids = bssids_by_target.get(streak.get("target")) or set()
            if sta_bssids:
                for f in in_win:
                    if f.subtype not in ("10", "12") or f.ra != BROADCAST:
                        continue
                    if (f.ta in sta_bssids or f.bssid in sta_bssids) and f not in scoped:
                        scoped.append(f)
        # DeAuth(12)는 is_roaming_related(ROAMING_SUBTYPES)가 이미 포함하므로
        # 여기선 그것만으로 안 잡히는 DisAssoc(10)만 보강한다.
        roam = [f for f in scoped if f.is_roaming_related or f.subtype == "10"]
        data_frames = [f for f in scoped if f.is_data]
        retry_frames = [f for f in data_frames if f.retry]
        retry_pct = (len(retry_frames) * 100.0 / len(data_frames)) if data_frames else 0.0
        retry_burst = (
            len(retry_frames) >= _WIRED_LOSS_RETRY_MIN
            and retry_pct >= _WIRED_LOSS_RETRY_PCT
        )
        cliffs = _cliffs_overlapping_window(signal_cliffs, win, cliff_names)

        reasons = []
        if roam:
            reasons.append(f"로밍/해제 {len(roam)}건")
        if retry_burst:
            reasons.append(
                f"재전송 폭주({len(retry_frames)}/{len(data_frames)}={retry_pct:.0f}%)"
            )
        if cliffs:
            reasons.append(f"RSSI 절벽 {len(cliffs)}건")

        head = (f"유선 확정 손실 {streak.get('count')}건 "
                f"({streak.get('target', '?')}, {streak.get('duration_sec')}초)")
        if reasons:
            # 매핑 실패 시 귀속이 불확실하므로 severity를 medium으로 낮춘다
            # (근거·메시지는 그대로 보존 — 정보 자체는 여전히 유용하다).
            severity = "high" if mapped else "medium"
            # refs: 창 안 로밍/retry 프레임(폭주 미달이라도)에, cliff가 있으면
            # cliff 시각 근처 프레임(_cliff_frame_refs)을 더한다 — 각 근거가
            # msg에 적은 사유와 실제로 대응하도록. 끝내 아무것도 못 찾으면
            # 스코프 전체로 폴백한다(근거 없는 결론 금지의 최후 수단).
            anomaly = {f.number for f in roam} | {f.number for f in retry_frames}
            if cliffs:
                anomaly.update(_cliff_frame_refs(cliffs, signal_stas, frames, index))
            refs = sorted(anomaly) if anomaly else [f.number for f in scoped]
            issue = {
                "severity": severity, "category": "유선 손실",
                "msg": f"{head} — 구간 내 무선: {', '.join(reasons)} ({sta_label})",
                "action": "통합 타임라인에서 해당 구간의 로밍·재전송·RSSI를 확인하세요.",
            }
        else:
            issue = {
                "severity": "medium", "category": "유선 손실",
                "msg": (f"{head} — 구간 내 무선 이상 징후 없음 "
                        f"(트래픽 {len(scoped)}건 정상, {sta_label})"),
                "action": "무선 구간 외 원인(유선/AP 상위단)을 의심하세요.",
            }
            refs = [f.number for f in scoped]
        out.append({"issue": issue, "refs": refs, "window": win,
                    "signal_type": "wired_loss"})
    return out


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
    # 판정 분모 술어는 roaming이 단일 정의 — 전체 점수와 STA별 점수가 같은 모집단을
    # 쓴다. 함수 안 import는 _structured_roaming과 같은 순환 회피 패턴.
    from ..core.modules.roaming import is_decided

    ov = structured.get("overview", {})
    ping = structured.get("ping", {})
    roaming = structured.get("roaming", {})
    signal = structured.get("signal", {})
    device_stats = structured.get("device_stats", {})
    delays = structured.get("delay_zones", {})
    anomalies = structured.get("anomaly_frames", {})

    frames = frames or []
    # 결과 JSON에는 losses 키가 없다(full_list 중복이라 제거) — 헬퍼가 파생한다.
    ping_loss_items = _ping_losses(ping)

    total_frames = ov.get("total_frames", 0)
    retry_pct = ov.get("retry_pct", 0)
    ping_stats = ping.get("stats", {})
    loss_pct = ping_stats.get("loss_pct", 0)
    roam_seqs = roaming.get("sequences", [])
    slow_roams = [s for s in roam_seqs if s.get("is_slow")]

    # ping 측정 가능 여부 — request+reply가 전혀 없는 캡처(ICMP 없음)에서
    # loss 컴포넌트를 100점 만점 처리하면 건강도가 부풀려진다. 이 경우 loss
    # 점수를 None(측정 불가)으로 두고 가용 컴포넌트만으로 가중 재분배한다.
    # 구버전 직렬화 result에는 req_total_raw 류 키가 없을 수 있어 pairs/losses
    # 존재 여부를 함께 본다.
    ping_available = bool(
        _ping_pairs(ping) or ping_loss_items
        or ping_stats.get("req_total_raw") or ping_stats.get("reply_total_raw")
    )

    retry_score = max(0, 100 - retry_pct * 5)
    # gap 측정 불가 시퀀스는 느린지 아닌지 **알 수 없다**. 분모에 그대로 넣으면
    # "느린 로밍 비율"이 희석돼 점수가 낙관적으로 부풀려진다 — 극단적으로 전량
    # 측정 불가면 만점이 나와 "캡처가 나쁠수록 건강해 보이는" 역전이 생긴다.
    # 측정된 시퀀스만 분모로 쓰고, 하나도 없으면 loss와 같이 None(측정 불가)으로
    # 두어 아래 가중치 재정규화에 태운다.
    # "판정 가능"의 기준은 gap 유무가 아니라 **느린 로밍 판정이 섰는지**다 —
    # 술어는 roaming.is_decided(단일 소스)이며 STA별 점수도 같은 것을 쓴다
    # (자세한 근거는 그 함수 docstring).
    measurable_roams = [seq for seq in roam_seqs if is_decided(seq)]
    if not roam_seqs:
        roam_score = 100          # 로밍 자체가 없음 = 문제 없음
    elif not measurable_roams:
        roam_score = None         # 로밍은 있으나 전부 측정 불가 = 판정 불가
    else:
        slow_ratio = len(slow_roams) / len(measurable_roams) * 100
        roam_score = max(0, 100 - slow_ratio * 2)

    # 손실 판정은 **유선 ground truth가 있으면 그것을 쓴다**(프로젝트 대원칙:
    # 판정 유선 1차·해석 무선 보조). 무선 관측 손실률은 모니터가 놓친 프레임까지
    # 손실로 세므로 실제보다 크다 — 실측 2시간 캡처에서 유선 0.38% vs 무선 8.24%로
    # **20배** 차이였고, 가중치가 가장 큰 축(0.4)이라 건강도가 통째로 달라진다.
    # 무선 값으로 판정하면 "모니터가 나쁠수록 네트워크가 나빠 보이는" 역전이다
    # (측정 불가를 정상으로 세던 로밍 분모 오염과 같은 종류의 오류).
    #
    # 무선 관측값도 버리지 않는다 — summary에 그대로 남겨 두 값의 차이가 곧
    # 캡처 커버리지를 말해준다. 어느 쪽으로 판정했는지는 `loss_basis`로 드러낸다.
    loss_pct_used, loss_basis = _loss_for_judgment(ping, loss_pct, ping_available)
    loss_score = (
        max(0, 100 - loss_pct_used * 10) if loss_pct_used is not None else None
    )

    # 컴포넌트 가중치 단일 정의 — 측정 불가(None) 컴포넌트는 제외하고
    # 가용 가중치 합으로 정규화한다. 컴포넌트 추가/가중치 변경 시 이 dict만 수정.
    weighted_scores = {
        "retry": (retry_score, 0.3),
        "loss": (loss_score, 0.4),
        "roaming": (roam_score, 0.3),
    }
    available = [(v, w) for v, w in weighted_scores.values() if v is not None]
    total_weight = sum(w for _, w in available)
    health_score = round(sum(v * w for v, w in available) / total_weight)
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
        # 전체 점수와 **같은 술어**(roaming.is_decided)로 분모를 잡는다 — 측정 불가는
        # 분모에서 뺀다(계수 200이라 왜곡 폭이 전체 점수의 2배다). 전부 측정 불가면
        # 로밍 컴포넌트를 빼고 재정규화한다.
        sta_measurable = [s for s in sta_roams if is_decided(s)]
        if not sta_roams:
            s_roam = 100
        elif not sta_measurable:
            s_roam = None
        else:
            s_roam = max(0, 100 - len(sta_slow_roams) / len(sta_measurable) * 200)
        # STA 로그 대조는 **점수에 넣지 않는다** — 관측 커버리지는 네트워크 품질이
        # 아니라 캡처의 성질이라, 점수화하면 "로그를 안 올리면 건강해 보이는"
        # 역전이 생긴다. 노출만 하고 가중치에서는 뺀다.
        sta_log_matched, sta_log_p50, _, _ = _roam_coverage(sta_roams)
        _sta_weights = [(s_retry, 0.35), (s_rssi, 0.35), (s_roam, 0.3)]
        _sta_avail = [(v, w) for v, w in _sta_weights if v is not None]
        s_overall = round(
            sum(v * w for v, w in _sta_avail) / sum(w for _, w in _sta_avail)
        )

        issues = []

        def _add_issue(issue, refs, window, signal_type=None):
            # 근거(frame_refs+time_window)를 댈 수 있을 때만 issue 채택.
            # signal_type은 causality.build_correlations가 종합 결론을
            # 만들 때 신호 분류 키로 사용한다(기존 소비자는 무시 가능).
            if ev._attach(issue, refs, window):
                if signal_type:
                    issue["signal_type"] = signal_type
                issues.append(issue)

        sta_retry_sev = retry_severity(sta_retry)
        if sta_retry_sev == "danger":
            refs, window = ev.retry_bucket_evidence(mac, index)
            _add_issue(
                {
                    "severity": "high",
                    "msg": f"Retry율 {sta_retry}% (임계치 {RETRY_DANGER_PCT}% 초과)",
                    "action": "TX power 또는 안테나 확인, 로밍 임계값 조정",
                },
                refs, window, signal_type="high_retry",
            )
        elif sta_retry_sev == "warn":
            refs, window = ev.retry_bucket_evidence(mac, index)
            _add_issue(
                {
                    "severity": "medium",
                    "msg": f"Retry율 {sta_retry}%",
                    "action": "채널 혼잡도 확인",
                },
                refs, window, signal_type="high_retry",
            )
        # PHY/MCS retry 핫스팟 — 특정 PHY+MCS에 retry가 집중된 경우. 표본>=30 &
        # retry_pct가 STA 평균의 2배 또는 50% 이상인 버킷 중 최악 1건만 emit
        # (issue flooding 방지). 근거는 그 PHY+MCS의 retry 프레임.
        mcs_retry_by_phy = ds.get("mcs_retry_by_phy", {})
        hotspot_threshold = max(50, sta_retry * 2)
        hotspots = []
        for phy, mcs_map in mcs_retry_by_phy.items():
            for mcs_key, r in mcs_map.items():
                if r.get("total", 0) >= 30 and r.get("retry_pct", 0) >= hotspot_threshold:
                    hotspots.append((phy, mcs_key, r))
        if hotspots:
            phy, mcs_key, r = max(hotspots, key=lambda x: x[2].get("retry_pct", 0))
            retry_pct_h = r.get("retry_pct", 0)
            total_h = r.get("total", 0)
            retry_h = r.get("retry", 0)
            label = (
                f"Legacy {mcs_key}Mbps" if phy == "Legacy" else f"{phy} MCS{mcs_key}"
            )
            refs, window = ev.mcs_hotspot_evidence(mac, phy, mcs_key, frames, index)
            _add_issue(
                {
                    "severity": "high" if retry_pct_h >= 60 else "medium",
                    "msg": f"{label} retry {retry_pct_h}% ({retry_h}/{total_h}) — 특정 MCS 집중 재전송",
                    "action": "rate adaptation/간섭 점검, 해당 MCS 고정 사용 여부 확인",
                },
                refs, window, signal_type="mcs_hotspot",
            )
        # 신호 급강하(cliff) — RSSI 급강하가 2건 이상이거나 단일 drop>=15dB.
        # signal_cliffs는 직렬화 라운드트립에서 null이거나 dict 아닌 항목을 포함할 수
        # 있다(구버전 result 호환). `or {}` + isinstance로 방어해 진단 전체가 죽지 않게.
        sc_map = structured.get("signal_cliffs") or {}
        sta_cd = sc_map.get(sta_name) if isinstance(sc_map, dict) else None
        sta_cliffs = [
            c
            for c in ((sta_cd.get("cliffs") if isinstance(sta_cd, dict) else None) or [])
            if isinstance(c, dict)
        ]
        max_drop = max((c.get("drop_db", 0) for c in sta_cliffs), default=0)
        if len(sta_cliffs) >= 2 or max_drop >= 15:
            refs, window = ev.cliff_evidence(mac, sta_cliffs, frames, index)
            severe = len(sta_cliffs) >= 3 or max_drop >= 20
            _add_issue(
                {
                    "severity": "high" if severe else "medium",
                    "msg": f"신호 급강하 {len(sta_cliffs)}건 (최대 {max_drop}dB)",
                    "action": "AP 커버리지/간섭 점검, 로밍 임계값 조정",
                },
                refs, window, signal_type="signal_cliff",
            )
        rssi_sev = rssi_severity(rssi_avg) if rssi_avg is not None else "good"
        if rssi_sev == "danger":
            refs, window = ev.weak_rssi_evidence(mac, RSSI_DANGER_DBM, frames, index)
            _add_issue(
                {
                    "severity": "high",
                    "msg": f"RSSI 평균 {rssi_avg}dBm (약함)",
                    "action": "AP 위치 조정 또는 TX power 증가",
                },
                refs, window, signal_type="weak_rssi",
            )
        elif rssi_sev == "warn":
            refs, window = ev.weak_rssi_evidence(mac, RSSI_WARN_DBM, frames, index)
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
                    "msg": (
                        f"느린 로밍 {len(sta_slow_roams)}회 "
                        f"(전체 소요 >{ROAM_GAP_DANGER_MS}ms)"
                    ),
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
                    # 그 STA의 로밍이 전부 판정 불가면 None(측정 불가) — 전체
                    # component_scores.roaming과 같은 규약이다. 0으로도 100으로도
                    # 쓰면 안 된다(모르는 값을 점수로 단정하는 것).
                    "roaming": round(s_roam) if s_roam is not None else None,
                },
                "metrics": {
                    "retry_pct": sta_retry,
                    "rssi_avg": rssi_avg,
                    "rssi_min": rssi_min,
                    "roaming_count": len(sta_roams),
                    "slow_roaming": len(sta_slow_roams),
                    # 느림 판정이 선 로밍 수 — slow_roaming의 실제 분모.
                    "roaming_measurable": len(sta_measurable),
                    # STA 로그와 대조된 로밍 수와 그 체감 중앙값. 대조 분모를 함께
                    # 내지 않으면 체감값이 전건 기준으로 읽힌다(로그는 일부만 붙는다).
                    # 로그가 없으면 0/None — 판정에는 쓰이지 않는다.
                    "sta_log_matched": sta_log_matched,
                    "sta_log_total_ms_p50": sta_log_p50,
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

    if retry_pct > RETRY_DANGER_PCT:
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
    # 네트워크 Legacy 송신 과다 — system_stats per_bucket의 legacy_pct를 tx-weighted
    # 평균. 30% 이상이면 채널 전반 레거시 오염으로 보고(기존 retry issue와 중복 X).
    system_stats = structured.get("system_stats", {})
    sys_buckets = system_stats.get("per_bucket", []) if system_stats else []
    legacy_num = sum(
        b.get("legacy_pct", 0) * b.get("tx_total", 0)
        for b in sys_buckets if b.get("tx_total", 0) > 0
    )
    legacy_den = sum(b.get("tx_total", 0) for b in sys_buckets if b.get("tx_total", 0) > 0)
    avg_legacy_pct = round(legacy_num / legacy_den, 1) if legacy_den else 0
    if avg_legacy_pct >= 30:
        refs, window = ev.network_legacy_evidence(frames, index)
        _add_net_issue(
            {
                "severity": "medium",
                "category": "PHY",
                "msg": f"네트워크 Legacy 송신 비율 {avg_legacy_pct}%",
                "action": "레거시 단말/브로드캐스트 레이트·기본 rate 설정 점검",
            },
            refs, window, signal_type="legacy_heavy",
        )
    # 건강도와 **같은 값**으로 판정한다 — 점수는 유선 확정으로 계산해 놓고 이슈만
    # 무선 관측으로 올리면, 리포트가 "손실 96점"과 "Ping Loss 8.24% high"를 나란히
    # 말하는 자기모순이 된다. 근거 프레임은 무선에서만 소싱할 수 있으므로(유선
    # frame.number를 섞으면 프레임 테이블 조회가 깨진다) 무선 손실 근거가 없으면
    # `_add_net_issue`가 이 이슈를 드롭한다 — 유선 확정 손실의 상세는
    # `_ground_truth_issue_candidates`가 streak별로 따로 낸다.
    if loss_pct_used is not None and loss_pct_used > LOSS_DANGER_PCT:
        refs, window = ev.ping_loss_evidence(ping_loss_items)
        basis_label = LOSS_BASIS_LABELS.get(loss_basis, "")
        _add_net_issue(
            {
                "severity": "high",
                "category": "Ping",
                "msg": f"Ping Loss {loss_pct_used}%" + (f" ({basis_label})" if basis_label else ""),
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
    # 로밍 관측 커버리지 — pcap이 로밍의 일부만 본다는 **해석 경고**.
    # 네트워크 문제가 아니라 측정 한계라 category를 "관측"으로 분리하고 severity도
    # high로 올리지 않는다. 건강도에도 넣지 않는다(판정 축 불변).
    #
    # `signal_type`을 주지 않는 것이 의도적이다 — causality는 cluster 안 distinct
    # signal_type 수로 confidence를 정하는데(`causality.py:282-285`), 커버리지는
    # 특정 시각의 사건이 아니라 캡처 전체의 성질이라 time_window가 어떤 cluster와도
    # 겹쳐 인과 confidence를 부풀린다. signal_type 없는 issue는 `_collect_signals`가
    # 그냥 지나치며(`:158`, `:178`), STA issue 승격 경로도 이미 안 붙인다.
    cov_matched, cov_sta_p50, cov_pcap_p50, cov_visible_pct = _roam_coverage(roam_seqs)
    cov_reportable = coverage_is_reportable(cov_matched, cov_visible_pct)
    if cov_reportable and cov_visible_pct < ROAM_COVERAGE_LOW_PCT:
        matched_seqs = [
            s for s in roam_seqs
            if isinstance(s, dict) and isinstance(s.get("sta_log"), dict)
        ]
        refs, window = ev.roaming_evidence(matched_seqs)
        _add_net_issue(
            {
                "severity": "medium",
                "category": "관측",
                "msg": (
                    f"로밍 관측 커버리지 {cov_visible_pct}% — pcap {cov_pcap_p50}ms "
                    f"vs STA 체감 {cov_sta_p50}ms (같은 로밍 {cov_matched}건 대조)"
                ),
                "action": (
                    "느린 로밍 판정은 전파 구간 기준이다. 스캔·로밍 판단·드라이버 "
                    "처리·키 설치는 캡처에 나타나지 않으므로 STA 로그와 함께 해석할 것"
                ),
            },
            refs, window,
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
        dz_refs, _ = ev.ping_loss_evidence(ping_loss_items)
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

    # 유선 ground truth 손실 구간 ↔ 무선 이벤트 대조 (스펙 §4)
    # ap_macs: sender→STA 매핑에서 AP를 배제하기 위한 집합. signal["aps"]는
    # _structured_signal이 roles의 role=="AP"에서 만든 것이라 detect_roles의 AP
    # 집합과 동일하다 — roles를 진단 함수까지 새로 넘기지 않고 같은 출처를 쓴다
    # (cliff 매핑이 쓰는 signal["stas"]와 대칭).
    ap_macs = {
        info.get("mac") for info in (signal.get("aps") or {}).values()
        if isinstance(info, dict) and info.get("mac")
    }
    for cand in _ground_truth_issue_candidates(
        ping.get("ground_truth") or {}, frames or [], structured.get("signal_cliffs"),
        signal.get("stas"), index, ap_macs,
    ):
        _add_net_issue(cand["issue"], cand["refs"], cand["window"],
                       signal_type=cand["signal_type"])

    severity_order = {"high": 0, "medium": 1, "low": 2}
    all_issues.sort(key=lambda x: severity_order.get(x["severity"], 3))

    result = {
        "health": {"score": health_score, "grade": health_grade, "color": health_color},
        "component_scores": {
            "retry": round(retry_score),
            # None = 측정 불가(ICMP 없음). JSON에는 null로 직렬화되며 구버전
            # result(숫자)와 소비자(charts.js/report.py)가 모두 분기 처리한다.
            "loss": round(loss_score) if loss_score is not None else None,
            # 측정 불가면 None — loss와 동일 규약(소비자가 분기 처리).
            "roaming": round(roam_score) if roam_score is not None else None,
        },
        "summary": {
            "total_frames": total_frames,
            "retry_pct": retry_pct,
            # 무선 관측값 — 기존 키·의미 그대로 유지(구버전 소비자 호환).
            "loss_pct": loss_pct if ping_available else None,
            # 건강도·이슈가 **실제로 판정에 쓴** 값과 그 근거. 유선 GT가 있으면
            # loss_pct와 다르며, 두 값의 차이가 곧 캡처 커버리지를 말해준다.
            "loss_pct_used": loss_pct_used,
            "loss_basis": loss_basis,
            "roaming_total": len(roam_seqs),
            "roaming_slow": len(slow_roams),
            # 느린 로밍 비율의 실제 분모와, 판정 불가 건수를 숨기지 않는다 —
            # 이게 없으면 "총 N회 중 느린 M회"가 정상 비율처럼 읽힌다.
            "roaming_measurable": len(measurable_roams),
            "roaming_unmeasured": len(roam_seqs) - len(measurable_roams),
            # STA 로그 대조 — pcap이 로밍의 몇 %를 보는가. **판정에는 쓰지 않는다**
            # (임계의 운용 근거가 아직 없다). 두 중앙값을 함께 실어 비율의 유도를
            # 검증할 수 있게 하고, 대조 0건이면 비율은 0%가 아니라 null이다.
            "roaming_sta_log_matched": cov_matched,
            "roaming_sta_total_ms_p50": cov_sta_p50,
            "roaming_pcap_total_ms_p50": cov_pcap_p50,
            "roaming_pcap_visible_pct": cov_visible_pct,
            # 표본이 충분해 비율을 단정해도 되는가. 리포트·화면이 각자 판단하면
            # 진단과 갈라지므로(PR #31 Codex P2) 판단 결과를 실어 보낸다.
            "roaming_coverage_reportable": cov_reportable,
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
