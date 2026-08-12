"""STA 로그 ↔ pcap 상관 — 어느 호기가 어느 STA인지, 시계는 얼마나 어긋났는지.

로그와 pcap을 같은 축에 올리려면 두 가지가 필요하다.

**1) 신원 매칭.** 폴더명(`1호기`)으로 STA를 추론하면 안 된다 — 실측에서
1호기=STA2, 2호기=STA3, 3호기=STA1로 **번호가 어긋난다**. `kern.log`의
`bridge: wlan IPv4 updated`가 주는 STA 자기 IP를, pcap에서 관측한 MAC↔IP
바인딩과 조인해 결정한다.

**2) 시계 정렬.** 로그 타임스탬프는 타임존 없는 벽시계이고 캡처 장비 시계와
어긋나 있다(실측 +2.744초). 보정 없이 상관시키면 전부 빗나간다. 여기서는 NTP
프레임 추출 같은 외부 의존 없이 **로밍 시각 분포를 직접 상호상관**해 오프셋을
추정한다 — 로밍이 STA마다 다른 시각에 일어나므로 정답 짝의 잔차만 뚜렷하게
작아진다(실측 정답쌍 MAD 20ms vs 오답쌍 4.7~9.5초로 500배 분리).
"""
import statistics
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: 오프셋 후보 탐색 범위(초). 캡처 장비와 STA가 같은 NTP를 봐도 수 초 어긋날 수
#: 있고(실측 +2.74s), 수동 설정 환경이면 더 클 수 있다.
OFFSET_SEARCH_SEC = 30.0
#: 오프셋 추정 시 같은 로밍으로 볼 1차 창(초). 로밍 주기(~20초)보다 충분히 작아야
#: 엉뚱한 로밍끼리 짝지어지지 않는다.
COARSE_WINDOW_SEC = 3.0
#: 최종 매칭 허용 오차(초). 실측상 로그→공중 지연이 ~110ms이고 산포가 ±170ms라
#: 200ms면 적중 94~96%다.
MATCH_TOLERANCE_SEC = 0.2
#: 이 개수보다 적게 매칭되면 신뢰할 수 없는 짝으로 본다.
MIN_MATCHES = 5
#: 타임존 차이를 스냅할 격자(초) = 15분. 현존하는 UTC 오프셋은 모두 15분 배수라
#: 이 격자면 서버/로그 타임존이 달라도 정확히 걷어낸다. 시계 오차(수 초)를
#: 잘못 스냅하지 않도록 OFFSET_SEARCH_SEC를 넘는 차이에만 적용한다.
TZ_SNAP_SEC = 900.0

#: 바인딩 방법(`StationBinding.method`) → 표시 라벨. 리포트·AI 프롬프트·화면이
#: 같은 어휘를 쓰도록 여기 한 곳에만 둔다.
#:
#: **실패(`""`)는 의도적으로 이 맵에 없다.** 실패를 방법 이름으로 렌더하면
#: "매칭 실패(시각 상관)"처럼 **하지도 않은 근거를 주장**하게 된다(PR #31 Codex P2 —
#: prompts.py가 `== "ip"`가 아니면 전부 "시각 상관"으로 찍어 AI에게 거짓 근거를
#: 줬다). 소비자는 `sta_name` 유무로 성공/실패를 **먼저** 가른 뒤 이 맵을 쓰고,
#: 모르는 값은 `.get()`으로 걸러 방법을 주장하지 않는다.
MATCH_METHOD_LABELS = {"ip": "IP", "time": "시각 상관"}


def pcap_ip_bindings(frames: Sequence[Any]) -> Dict[str, str]:
    """pcap 프레임에서 관측한 **IP → 송신 MAC** 바인딩.

    STA가 자기 IP로 보낸 프레임(`ta`가 그 MAC, `ip_src`가 그 IP)만 센다 —
    수신(ra/ip_dst) 쪽을 섞으면 상대편 IP가 그 MAC에 붙는다. 같은 IP에 여러
    MAC이 보이면 최빈값을 쓴다(A-MSDU 등으로 콤마 결합된 값은 버린다).

    하드코딩 매핑표를 두지 않기 위한 함수다 — 캡처마다 IP가 달라도 동작한다.
    """
    counts: Dict[str, Dict[str, int]] = {}
    for f in frames:
        mac = (getattr(f, "ta", "") or "").lower()
        ip = getattr(f, "ip_src", "") or ""
        if not mac or not ip or "," in mac or "," in ip:
            continue
        counts.setdefault(ip, {})
        counts[ip][mac] = counts[ip].get(mac, 0) + 1
    return {
        ip: max(macs, key=lambda m: macs[m]) for ip, macs in counts.items() if macs
    }


def estimate_offset(
    log_epochs: Sequence[float],
    pcap_epochs: Sequence[float],
    search_sec: float = OFFSET_SEARCH_SEC,
) -> Tuple[Optional[float], int, float]:
    """로그 시각 → pcap 시각으로 옮기는 오프셋을 추정한다.

    `pcap_epoch ≈ log_epoch + offset` 이 되는 offset을 찾는다.

    방법: 두 시각 목록의 모든 쌍 차이 중 탐색 범위 안의 것을 모아 **최빈 구간**을
    찾고(0.1초 버킷 히스토그램), 그 구간 값들의 중앙값을 오프셋으로 쓴다.
    평균이 아니라 중앙값인 이유는 우연히 가까운 엉뚱한 쌍이 섞이기 때문이다.

    Returns:
        (offset, 매칭 수, 잔차 MAD). 추정 실패면 (None, 0, inf).
        MAD(중앙절대편차)가 작을수록 그 짝이 맞다는 뜻이다 — 정답 짝은 수십 ms,
        오답 짝은 수 초로 뚜렷하게 갈린다.
    """
    if not log_epochs or not pcap_epochs:
        return None, 0, float("inf")

    pcap_sorted = sorted(pcap_epochs)
    # 후보 셋을 모두 재고 **가장 많이 매칭된 것**을 고른다.
    #  · 보정 없음 — 시계가 맞는 정상 경로.
    #  · 15분 격자 스냅 — STA 로그에는 타임존이 없어 파서가 **분석 서버의 로컬
    #    타임존**으로 읽는다(station_log._parse_ts). 서버 UTC + 로그 KST면 9시간
    #    어긋나 ±30초 탐색으로는 한 쌍도 못 찾는다(개발 호스트가 KST라 드러나지
    #    않았다). 타임존 차이는 반드시 15분 배수라 격자에 정확히 떨어진다.
    #  · 중앙값 차이 그대로 — 폐쇄망/NTP 부재 장비는 시계가 **임의의** 값만큼
    #    어긋난다(수 분~수십 분). 격자에 스냅하면 3분 오차는 0으로 반올림돼 무용하다.
    #
    # **보정 없음이 조건을 만족해도 조기 확정하지 않는다.** 로밍 간격이 규칙적이면
    # 큰 시계 오차가 그 주기로 접혀 들어와(에일리어싱) 틀린 오프셋이 잔차 0으로
    # 그럴듯하게 맞는다 — 실측 재현: 20초 주기 로밍에 187초 오차를 주면 보정 없음이
    # 27.11초에서 12건을 맞히지만 올바른 187.11초는 20건 전부를 맞힌다.
    #
    # 동점이면 앞 후보(보정 없음)를 유지하므로 보정이 없는 쪽보다 나빠지지 않는다.
    # 관측 구간이 크게 다르면(로그 24시간 vs 캡처 10분) 중앙값 차이가 시계와
    # 무관하게 커지는데, 그 후보는 매칭이 적어 자연히 탈락한다.
    gap = statistics.median(pcap_epochs) - statistics.median(log_epochs)
    best = _search_offset(log_epochs, pcap_sorted, search_sec)
    seen = {0.0}
    for coarse in (round(gap / TZ_SNAP_SEC) * TZ_SNAP_SEC, gap):
        if coarse in seen:
            continue
        seen.add(coarse)
        got = _search_offset([le + coarse for le in log_epochs], pcap_sorted, search_sec)
        if got[1] > best[1]:
            best = (coarse + got[0], got[1], got[2])
    return best


def _search_offset(
    log_epochs: Sequence[float], pcap_sorted: Sequence[float], search_sec: float
) -> Tuple[Optional[float], int, float]:
    """탐색 범위 안에서만 오프셋을 찾는다(`estimate_offset`의 핵심 루프)."""
    buckets: Dict[int, List[float]] = {}
    for le in log_epochs:
        lo = bisect_left(pcap_sorted, le - search_sec)
        for pe in pcap_sorted[lo:]:
            d = pe - le
            if d > search_sec:
                break
            if -search_sec <= d <= search_sec:
                buckets.setdefault(int(d * 10), []).append(d)
    if not buckets:
        return None, 0, float("inf")

    best_key = max(buckets, key=lambda k: len(buckets[k]))
    # 인접 버킷까지 합쳐 경계에 걸친 표본을 잃지 않는다.
    pool = buckets.get(best_key - 1, []) + buckets[best_key] + buckets.get(best_key + 1, [])
    offset = statistics.median(pool)

    # 그 오프셋으로 실제 매칭해 잔차를 잰다.
    residuals: List[float] = []
    for le in log_epochs:
        t = le + offset
        i = bisect_left(pcap_sorted, t)
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(pcap_sorted):
                r = pcap_sorted[j] - t
                if best is None or abs(r) < abs(best):
                    best = r
        if best is not None and abs(best) <= COARSE_WINDOW_SEC:
            residuals.append(best)
    if not residuals:
        return offset, 0, float("inf")
    med = statistics.median(residuals)
    mad = statistics.median([abs(r - med) for r in residuals]) if len(residuals) > 1 else 0.0
    # 중앙 잔차만큼 한 번 더 당겨 최종 오프셋을 다듬는다.
    return offset + med, len(residuals), mad


@dataclass
class StationBinding:
    """호기 로그 하나가 어느 pcap STA에 붙었는지와 그 근거."""
    log_name: str
    sta_mac: str = ""
    sta_ip: str = ""
    offset_sec: Optional[float] = None
    matched: int = 0
    residual_mad_ms: float = float("inf")
    method: str = ""          #: "ip" | "time" | "" (실패)
    warnings: List[str] = field(default_factory=list)


def bind_stations(
    stations: Sequence[Any],
    frames: Sequence[Any],
    roam_epochs_by_sta: Dict[str, List[float]],
) -> List[StationBinding]:
    """호기 로그들을 pcap STA에 붙이고 시계 오프셋을 추정한다.

    Args:
        stations: `station_log.StationLog` 목록.
        frames: pcap 프레임(IP↔MAC 바인딩 추출용).
        roam_epochs_by_sta: pcap에서 뽑은 {STA MAC: [로밍 시각들]}.

    신원은 IP로 먼저 정하고(1차), IP가 없거나 pcap에서 그 IP를 못 보면 **로밍
    시각 상관**으로 폴백한다(2차). 두 경로 모두 실패하면 붙이지 않는다 —
    잘못 붙이면 다른 STA의 로그를 그 STA 것으로 보고하게 된다.
    """
    ip_to_mac = pcap_ip_bindings(frames)
    used: set = set()
    out: List[StationBinding] = []

    for st in stations:
        b = StationBinding(log_name=st.name, sta_ip=st.sta_ip)
        log_epochs = [r.cmd_epoch for r in st.roams if not r.failed]

        # ── 1차: IP 매칭 ──
        mac = ip_to_mac.get(st.sta_ip, "") if st.sta_ip else ""
        if mac and mac not in used:
            b.sta_mac, b.method = mac, "ip"
        elif mac and mac in used:
            b.warnings.append(
                f"IP {st.sta_ip}가 이미 다른 로그에 배정된 STA({mac})를 가리킨다 — 시각 상관으로 재시도"
            )
            mac = ""

        # ── 2차: 로밍 시각 상관 ──
        if not b.sta_mac:
            best = (None, 0, float("inf"), None)   # (mac, matched, mad, offset)
            for cand, eps in roam_epochs_by_sta.items():
                if cand in used:
                    continue
                off, n, mad = estimate_offset(log_epochs, eps)
                if off is None or n < MIN_MATCHES:
                    continue
                if mad < best[2]:
                    best = (cand, n, mad, off)
            if best[0] is not None:
                b.sta_mac, b.method = best[0], "time"
                b.matched, b.residual_mad_ms, b.offset_sec = best[1], best[2] * 1000, best[3]
                if not st.sta_ip:
                    b.warnings.append("kern.log에 STA IP가 없어 로밍 시각 상관으로 매칭했다")

        if not b.sta_mac:
            b.warnings.append("pcap STA와 매칭하지 못했다 — 이 로그는 상관에서 제외된다")
            out.append(b)
            continue

        used.add(b.sta_mac)
        # 오프셋은 신원과 무관하게 항상 실측으로 다시 구한다(IP로 붙였어도 필요).
        if b.offset_sec is None:
            off, n, mad = estimate_offset(log_epochs, roam_epochs_by_sta.get(b.sta_mac, []))
            b.offset_sec, b.matched, b.residual_mad_ms = off, n, mad * 1000
        if b.offset_sec is None:
            b.warnings.append("시계 오프셋을 추정하지 못했다 — 구간 상관 불가")
        elif b.matched < MIN_MATCHES:
            b.warnings.append(
                f"오프셋 추정에 쓰인 로밍이 {b.matched}건뿐이라 신뢰도가 낮다"
            )
        out.append(b)
    return out


def attach_station_to_sequences(
    sequences: List[Dict[str, Any]],
    station: Any,
    binding: StationBinding,
    tolerance_sec: float = MATCH_TOLERANCE_SEC,
) -> int:
    """pcap 로밍 시퀀스에 그 STA 로그의 로밍 정보를 붙인다.

    **주의: `sequences`의 원소 dict를 직접 변형한다**(`seq["sta_log"] = ...`).
    호출 경로는 `pipeline._correlate_station_logs` 하나뿐이고 결과가 직렬화되기
    **전**에 실행되므로 지금은 안전하다. 캐시(`routes/analysis._read_result_cached`)
    에서 읽어온 dict를 넘기면 **캐시된 원본이 오염된다** — 그 캐시는 같은 객체를
    다음 요청에도 그대로 돌려준다.

    pcap 시퀀스의 시작 시각(`auth_epoch` 없으면 `assoc_epoch`)에 가장 가까운
    로그 로밍을 찾아 붙인다. `tolerance_sec` 밖이면 붙이지 않는다 — 억지로
    붙이면 다른 로밍의 값을 보고하게 된다.

    매칭은 **1:1**이다 — 로그 에피소드 하나는 시퀀스 하나에만 붙는다. 잔차가 작은
    쌍부터 확정하므로 결과는 `sequences`의 순서에 무관하다.

    붙는 필드(전부 신규, 기존 키는 건드리지 않는다):
        ``sta_log``: {
            "total_ms": ROAM 명령 → CONNECTED (STA 체감 로밍 전체),
            "assoc_ms": AUTHENTICATING 진입 → CONNECTED,
            "scan_ms": 직전 스캔 소요 (pcap이 못 보는 구간),
            "reason": 로밍 사유, "score": 후보 점수,
            "trigger_rssi"/"trigger_th": 트리거 임계 판단,
            "residual_ms": 로그 시각과 pcap 시각의 잔차(정렬 품질 지표),
        }

    Returns:
        실제로 붙인 시퀀스 수.
    """
    if binding.offset_sec is None or not binding.sta_mac:
        return 0
    roams = [r for r in station.roams if not r.failed and r.total_ms is not None]
    if not roams:
        return 0
    roam_t = [r.cmd_epoch + binding.offset_sec for r in roams]
    order = sorted(range(len(roams)), key=lambda i: roam_t[i])
    roam_t_sorted = [roam_t[i] for i in order]

    # **완료** 시각으로 정렬·탐색한다. 시작 시각으로 찾으면 ROAM 명령 시점에 아직
    # 진행 중이던 스캔이 "직전 스캔"으로 잡혀, 명령 이후 구간까지 포함한 duration이
    # 붙는다(과대계상). 겹치는 스캔이 있을 수 있어 시작 순서와 완료 순서가 다르므로
    # 정렬 키도 완료 시각이어야 한다.
    scans = sorted(station.scans, key=lambda s: s.done_epoch)
    scan_t = [s.done_epoch + binding.offset_sec for s in scans]

    decisions = sorted(station.decisions, key=lambda d: d.epoch)
    dec_t = [d.epoch + binding.offset_sec for d in decisions]

    # **1:1 매칭** — 후보를 모두 모아 잔차가 작은 쌍부터 확정하고, 쓴 로그 에피소드는
    # 폐기한다. 소비하지 않으면 허용오차(200ms) 안에 pcap 시퀀스가 여러 개일 때 같은
    # 에피소드가 **전부에 붙어** 표본이 부풀고 중앙값이 왜곡된다. 로밍 짝짓기에서
    # "앵커를 소비 즉시 폐기"로 고친 것과 같은 규칙이며, 그때는 낡은 앵커 재사용이
    # 32초짜리 허위 gap을 만들었다.
    #
    # 실측(2시간 캡처·부착 837건)에서는 재사용이 **0건**이었다 — 로밍 주기(~20초)가
    # 허용오차보다 훨씬 커서 한 에피소드 주변 200ms에 시퀀스가 둘 이상 놓이지 않는다.
    # 즉 이 방어는 아직 발동한 적이 없고 출력도 그대로다. 로밍이 촘촘하거나 시계
    # 정렬이 나쁜 캡처에서 조용히 틀리는 것을 선제적으로 막는다.
    #
    # 시퀀스 순서대로 greedy하면 앞 시퀀스가 더 먼 로그를 선점해 뒤 시퀀스가 굶는다 —
    # 후보를 전역으로 정렬해 결과가 입력 순서에 무관하게 만든다(정렬 키에 인덱스를
    # 넣어 동점도 결정적).
    #
    # **알려진 한계: 이 greedy는 최대 카디널리티를 보장하지 않는다.**
    # 잔차가 작은 간선부터 양 끝점을 소비하므로, 다른 배정이었으면 더 많이 붙일 수
    # 있는 경우를 놓친다. 시퀀스 A가 에피소드 둘 다와 매칭 가능하고 B는 하나만
    # 가능할 때, A가 그 하나를 먼저 가져가면 B는 굶는다(2건 가능한데 1건).
    # 정답은 최대 카디널리티 이분 매칭(Hopcroft-Karp 등)이고 잔차 합은 2차 목적이다.
    #
    # 지금 greedy로 두는 이유: 이 방어 자체가 실측에서 **한 번도 발동하지 않는다**.
    # 로밍 주기(~20초)가 허용오차(200ms)보다 훨씬 커서 한 에피소드 주변에 시퀀스가
    # 둘 이상 놓이지 않기 때문이다(2시간 캡처 837건에서 후보 충돌 0건). 발동하지도
    # 않는 경로에 매칭 알고리즘을 넣는 것은 복잡도만 늘린다.
    # **교체 시점**: 로밍이 촘촘하거나 시계 정렬이 나쁜 캡처에서 부착률이 설명 없이
    # 낮게 나오면 여기를 먼저 의심하고 최대 매칭으로 바꾼다.
    candidates = []      # (|잔차|, seq_idx, roam_idx, 잔차)
    for si, seq in enumerate(sequences):
        if (seq.get("sta") or "").lower() != binding.sta_mac:
            continue
        t = seq.get("auth_epoch")
        if not isinstance(t, (int, float)):
            t = seq.get("assoc_epoch")
        if not isinstance(t, (int, float)):
            continue
        i = bisect_left(roam_t_sorted, t)
        for j in (i - 1, i):
            if 0 <= j < len(roam_t_sorted):
                r = t - roam_t_sorted[j]
                if abs(r) <= tolerance_sec:
                    candidates.append((abs(r), si, order[j], r))
    candidates.sort()

    attached = 0
    used_seq: set = set()
    used_roam: set = set()
    for _, si, ri, best_r in candidates:
        if si in used_seq or ri in used_roam:
            continue
        used_seq.add(si)
        used_roam.add(ri)
        seq = sequences[si]
        ep = roams[ri]
        info: Dict[str, Any] = {
            "total_ms": round(ep.total_ms, 1),
            "assoc_ms": round(ep.assoc_procedure_ms, 1)
            if ep.assoc_procedure_ms is not None else None,
            "residual_ms": round(best_r * 1000, 1),
            "source": binding.log_name,
        }
        # 직전 스캔 — ROAM 명령 이전에 끝난 가장 가까운 스캔.
        k = bisect_left(scan_t, ep.cmd_epoch + binding.offset_sec)
        if k > 0:
            sc = scans[k - 1]
            info["scan_ms"] = round(sc.duration_ms, 1)
            info["scan_ap_count"] = sc.ap_count
        # 로밍 판단 근거 — ROAM 명령 직전의 결정.
        m = bisect_left(dec_t, ep.cmd_epoch + binding.offset_sec + 0.001)
        if m > 0:
            d = decisions[m - 1]
            info["reason"] = d.reason
            info["score"] = d.score
            info["trigger_rssi"] = d.trigger_rssi
            info["trigger_th"] = d.trigger_th
            info["trend"] = d.trend
        seq["sta_log"] = info
        attached += 1
    return attached
