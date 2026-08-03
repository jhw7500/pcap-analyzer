"""유선(포트 미러) pcap에서 ping ground truth를 만든다.

검증된 exping의 ICMP 추출·매칭 규칙(응답 인정 상한 1초)을 재사용한다 — 대시보드용
으로 EXPING xlsx 재현 규칙(RTT 정수 보정, 전각 문자열)은 쓰지 않고 Exchange 수준
에서 소비한다. docs/EXPING.md 참조.

sender 선정과 꼬리 무응답 판정은 EXPING 재구성(`exping.extract_exchanges`)과
다르게 동작한다 — 이 모듈만의 규칙이니 각 함수 docstring에 근거를 남긴다.
"""
import datetime as dt
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import exping
from .ping_matching import find_time_streaks

#: streaks 항목 수 상한 — 비정상 캡처(수천 구간)로 결과 JSON이 비대해지는 것 방지
MAX_STREAKS = 100
#: ng_epochs 상한 — 타임라인 마커용 샘플
MAX_NG_EPOCHS = 1000

#: 시간 필터 입력 형식 — 초 생략형도 허용
_TIME_FILTER_FORMATS: Tuple[str, ...] = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M")


def _parse_local_epoch(value: str) -> Optional[float]:
    """"YYYY-MM-DD HH:MM[:SS]" 문자열을 로컬 타임존 기준 epoch로 파싱.

    무선 쪽 extractor.build_tshark_cmd의 `frame.time >= "..."` 필터도 tshark가
    로컬 타임존으로 해석하므로, 이 함수도 로컬 타임존(datetime.timestamp())을
    써야 두 필터가 같은 구간을 가리킨다. 실패 시 None.
    """
    for fmt in _TIME_FILTER_FORMATS:
        try:
            return dt.datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    return None


def _filter_exchanges(
    exchanges: List["exping.Exchange"],
    sender: str,
    time_start: str,
    time_end: str,
    ip_filter: str,
) -> Tuple[Optional[List["exping.Exchange"]], str]:
    """시간/IP 필터를 적용한다. 파싱 실패 시 (None, 에러메시지)를 반환.

    mac_filter는 유선(비-802.11) exchange에 MAC 개념이 없어 적용하지 않는다
    (호출부인 pipeline.py 주석 참조).
    """
    out = exchanges
    if time_start:
        start_epoch = _parse_local_epoch(time_start)
        if start_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_start}"
        out = [x for x in out if x.time >= start_epoch]
    if time_end:
        end_epoch = _parse_local_epoch(time_end)
        if end_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_end}"
        out = [x for x in out if x.time < end_epoch]
    if ip_filter:
        ips = {ip.strip() for ip in ip_filter.split(",") if ip.strip()}
        # 무선 'ip.addr == X'는 src/dst 어느 쪽이든 매칭. sender는 이 캡처의
        # 모든 exchange에서 고정 src이므로, sender가 필터에 있으면 전부
        # 매칭되는 것과 같다(=필터링 없음). 아니면 target(=dst)으로 좁힌다.
        if ips and sender not in ips:
            out = [x for x in out if x.target in ips]
    return out, ""


def _cohort_requests(
    frames: List["exping.IcmpFrame"],
    time_start: str,
    time_end: str,
    ip_filter: str,
) -> Tuple[Optional[List["exping.IcmpFrame"]], str]:
    """echo request(icmp.type==8) 부분집합 — 시간 창·ip_filter로 좁힌 sender 후보군.

    sender는 "최다 요청 호스트"(exping.pick_sender)로 고르되, **전체 pcap이 아니라
    이 부분집합에서** 고른다. 전체에서 고르면(기존 extract_exchanges 방식) 배경
    호스트가 필터 구간 밖에서 sender보다 훨씬 많이 ping을 보냈을 때 그 배경 호스트가
    잘못 선택된다 — 필터가 있어도 무시된 채 전체 pcap 기준으로 sender가 확정되기
    때문이다.

    ip_filter는 여기서도 무선 쪽과 같은 tshark `ip.addr == X`대칭(src/dst 어느
    쪽이든 매칭)을 쓴다 — sender 자신의 IP를 몰라도, "이 IP가 요청의 src거나
    dst다"라는 조건은 성립한다. src만 보면 target IP만 준 ip_filter(예:
    "이 target에 ping하는 sender를 찾아라")가 코호트를 비워 에러를 내는데, 그건
    무선 필터 의미와도 어긋난다. dst까지 보면 그 경우도 "이 target에 ping한
    요청들"이 코호트가 되고 pick_sender가 그 요청들의 최다 송신자를 sender로
    고른다 — 이후 exchange 수준 `_filter_exchanges`(sender가 필터에 있으면 전체
    유지, 아니면 target 좁히기)가 최종 표시 범위를 정리한다.

    파싱 실패 시 (None, 에러메시지). 필터 결과가 빈 리스트일 수도 있다(빈 리스트
    자체가 유효한 반환값 — 호출부가 "필터 구간에 요청 없음"으로 처리).
    """
    start_epoch = end_epoch = None
    if time_start:
        start_epoch = _parse_local_epoch(time_start)
        if start_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_start}"
    if time_end:
        end_epoch = _parse_local_epoch(time_end)
        if end_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_end}"
    ips = {ip.strip() for ip in ip_filter.split(",") if ip.strip()} if ip_filter else None

    cohort = []
    for f in frames:
        epoch, src, dst, typ = f[0], f[1], f[2], f[3]
        if typ != exping.ICMP_ECHO_REQUEST:
            continue
        if start_epoch is not None and epoch < start_epoch:
            continue
        if end_epoch is not None and epoch >= end_epoch:
            continue
        if ips is not None and src not in ips and dst not in ips:
            continue
        cohort.append(f)
    return cohort, ""


def _detect_capture_end(pcap_path: str, tshark_path: str) -> Optional[float]:
    """capinfos로 실제 캡처의 마지막 패킷 시각(epoch)을 구한다. 실패/부재 시 None.

    ICMP 전용 필터(extract_icmp_frames)만으로는 캡처가 진짜 언제 끝났는지 알 수
    없다 — ping이 멈춘 뒤에도 non-ICMP 트래픽으로 캡처가 계속 이어질 수 있다.
    꼬리 무응답 판정(_drop_unreachable_tail)이 "물리적으로 응답이 잡힐 기회가
    없었다"를 증명하려면 ICMP 프레임이 아니라 pcap 자체의 끝을 알아야 한다.

    tshark와 같은 배포에 있는 capinfos를 우선 시도한다(버전 불일치 방지) —
    없으면 PATH에서 찾는다. `-e`(end time) `-M`(machine-readable) 만으로는 값이
    여전히 사람이 읽는 날짜 포맷("2023-11-15 07:13:21.703000")이다 — epoch
    초 단위로 받으려면 `-S`(seconds since epoch)를 함께 줘야 한다(실측:
    capinfos 4.4.9, `-e -M` → "2023-11-15 07:13:21.703000", `-e -S -M` →
    "1700000001.703000"). 라벨도 버전별로 다를 수 있어 "Latest packet time"과
    "End time" 둘 다 허용한다(실측 4.4.9는 전자).
    """
    candidates = []
    if tshark_path:
        candidates.append(str(Path(tshark_path).parent / "capinfos"))
    found = shutil.which("capinfos")
    if found:
        candidates.append(found)
    capinfos_path = next((c for c in candidates if c and Path(c).exists()), None)
    if not capinfos_path:
        return None
    try:
        result = subprocess.run(
            [capinfos_path, "-e", "-S", "-M", str(pcap_path)],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    if result.returncode != 0:
        return None
    for line in (result.stdout or "").splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("latest packet time") or stripped.startswith("end time"):
            _, _, value = line.partition(":")
            value = value.strip()
            if value:
                try:
                    return float(value.split()[-1])
                except ValueError:
                    return None
    return None


def _drop_unreachable_tail(
    exchanges: List["exping.Exchange"], capture_end: float, reply_timeout: float
) -> Tuple[List["exping.Exchange"], int]:
    """캡처 끝에서 reply_timeout 안에 있는 무응답 요청만 물리적 꼬리로 제외한다.

    exping.drop_trailing_unanswered("끝에서부터 무응답이면 전부 제외")는 EXPING
    재구성 전제(요청==응답인 로그, ping 세션이 끝나면 캡처도 끝남)에는 맞지만, 유선
    GT는 ICMP-only 필터로만 캡처를 보므로 pcap이 ping 세션보다 훨씬 길게 이어질 수
    있다 — 그 경우 창 안 마지막 자리에 우연히 놓인 **진짜 손실**까지 "꼬리라서
    판정 불가"로 오인해 지워 버린다(그래서 유선 GT 경로에서는 그 함수를 쓰지
    않는다). 대신 "응답이 reply_timeout 안에 도착할 물리적 기회가 있었는가"를
    직접 판정한다: 요청 시각이 `capture_end - reply_timeout` 이후면 응답이
    도착하기 전에 캡처가 끝났을 수 있으므로 제외하고, 그 이전이면(응답이 올
    시간이 충분히 있었는데 안 왔으면) 진짜 손실로 남긴다. 리스트 내 위치와
    무관하게 개별 요청 단위로 판정한다.
    """
    threshold = capture_end - reply_timeout
    kept: List["exping.Exchange"] = []
    dropped = 0
    for x in exchanges:
        if not x.answered and x.time > threshold:
            dropped += 1
            continue
        kept.append(x)
    return kept, dropped


def build_ground_truth(
    pcap_path: str,
    tshark_path: str = "tshark",
    reply_timeout: float = exping.DEFAULT_REPLY_TIMEOUT,
    time_start: str = "",
    time_end: str = "",
    ip_filter: str = "",
) -> Dict[str, Any]:
    """유선 pcap → ping ground truth dict. 실패 시 {"error": str, "warnings": [...]}.

    time_start/time_end/ip_filter는 무선 extract_frames()가 받는 동일 인자와
    같은 구간을 가리키도록 대칭으로 구현했다 — 서로 다른 구간을 비교하지 않기
    위함(무선 필터만 적용되고 유선은 전체 구간을 쓰면 손실률이 왜곡된다).

    처리 순서: ① 필터가 적용된 부분집합("코호트")에서 sender 선정(_cohort_requests)
    ② 무선 캡처 가드 ③ 전체 캡처 기준 요청↔응답 짝짓기(exping.pair_exchanges)
    ④ 캡처 끝 기준 물리적 꼬리 제거(_drop_unreachable_tail) ⑤ 시간/IP 필터로 최종
    표시 구간 좁히기(_filter_exchanges) ⑥ 집계. ③이 필터 이전(전체 캡처 기준)인
    이유: 창 끝 근처 요청의 응답이 창 밖(그러나 캡처 안)에 있어도 매칭돼야 한다.
    ④가 ⑤보다 먼저인 이유: 필터로 창을 먼저 자르면 창 안 마지막 자리의 진짜
    손실이 물리적 꼬리로 오인될 수 있다(trailing_dropped는 항상 물리적 꼬리 기준).

    취소 이벤트는 지원하지 않는다 — exping.extract_icmp_frames에 취소 훅이 없고
    child_timeout(기본 3600초) 상한만 있다. ICMP 디스플레이 필터라 대체로 빠르다.
    """
    warnings: List[str] = []
    try:
        frames = exping.extract_icmp_frames(pcap_path, tshark=tshark_path)
    except FileNotFoundError:
        return {"error": f"tshark 를 찾을 수 없다: {tshark_path}", "warnings": warnings}
    except (ValueError, TimeoutError) as exc:
        return {"error": str(exc), "warnings": warnings}

    cohort, err = _cohort_requests(frames, time_start, time_end, ip_filter)
    if cohort is None:
        return {"error": err, "warnings": warnings}
    if not cohort:
        if time_start or time_end or ip_filter:
            return {"error": "필터 구간에 echo request 가 없다", "warnings": warnings}
        return {"error": "ICMP echo request 가 없다", "warnings": warnings}

    try:
        sender = exping.pick_sender(cohort)
    except ValueError as exc:
        return {"error": str(exc), "warnings": warnings}

    # 무선 캡처 가드 — exping.extract_exchanges 내부 가드와 동일 의미를 유지하되,
    # 이 경로는 stderr 대신 warnings 리스트로 전달한다(웹 파이프라인은 stderr를
    # 사용자에게 보여주지 않는다). 판정은 전체 캡처(frames) 기준 — sender가 몇 %를
    # 무선으로 보냈는지는 필터 구간과 무관하게 이 캡처 자체의 성격이다.
    total_req, wireless_req = exping.count_wireless_requests(frames, sender)
    if wireless_req:
        if wireless_req == total_req:
            return {
                "error": (
                    f"무선(802.11) 캡처다 — 유선 캡처를 넣어라: {pcap_path}\n"
                    "  모니터가 못 들은 프레임이 전부 손실로 계산돼 손실률이 크게 "
                    "부풀려진다 (실측 0.16% 대 15.65%)."
                ),
                "warnings": warnings,
            }
        warnings.append(
            f"echo request {total_req:,}건 중 {wireless_req:,}건이 802.11 프레임이다 — "
            "인터페이스가 여럿인 캡처로 보인다. 같은 ping이 두 번 세어져 행 수와 "
            "손실률이 왜곡될 수 있다."
        )

    # 요청↔응답 짝짓기는 전체 캡처 기준(필터 이전) — 창 끝 근처 요청의 응답이
    # 창 밖(그러나 캡처 안)에 있어도 매칭돼야 하기 때문.
    exchanges = exping.pair_exchanges(frames, sender, reply_timeout)

    # drop 이전 체크: sender가 보낸 요청이 하나도 없는 경우 (pick_sender가 cohort에서
    # sender를 뽑은 이상 이론상 도달하지 않지만, 방어적으로 유지)
    if not exchanges:
        return {"error": f"{sender} 가 보낸 echo request 가 없다", "warnings": warnings}

    capture_end = _detect_capture_end(pcap_path, tshark_path)
    if capture_end is None:
        # capinfos 부재/실패 — 모든 ICMP 프레임(요청·응답·타 호스트 포함)의 최댓값을
        # 프록시로 쓴다. 실제 pcap 끝보다 이를 수 있어(비-ICMP 트래픽이 뒤에 더
        # 있을 수 있음) 꼬리 판정이 다소 보수적으로(더 많이 남기는 쪽으로) 치우칠
        # 수 있다는 한계를 warnings로 알린다.
        capture_end = max(f[0] for f in frames)
        warnings.append(
            "캡처 끝 시각을 확인하지 못해 ICMP 마지막 프레임으로 근사 "
            "(capinfos 부재 또는 파싱 실패)"
        )

    exchanges, dropped = _drop_unreachable_tail(exchanges, capture_end, reply_timeout)
    if dropped:
        warnings.append(
            f"꼬리 무응답 요청 {dropped}건 제외 — 캡처가 응답보다 먼저 끊긴 구간"
        )

    # drop 이후 체크: 요청은 있었지만 응답이 전부 없는 경우 (100% 손실이거나,
    # 전부 캡처 끝 근접이라 판정 불가한 경우 — 둘 다 exchanges가 빈다)
    if not exchanges:
        return {
            "error": f"응답 있는 요청이 하나도 없다 — 요청 {dropped}건 전부 무응답 (100% 손실이거나 미러 구성이 응답 방향을 놓친 캡처)",
            "warnings": warnings
        }

    if time_start or time_end or ip_filter:
        filtered, err = _filter_exchanges(exchanges, sender, time_start, time_end, ip_filter)
        if filtered is None:
            return {"error": err, "warnings": warnings}
        exchanges = filtered
        if not exchanges:
            return {"error": "필터 구간에 echo request 가 없다", "warnings": warnings}

    ng = [x for x in exchanges if not x.answered]
    targets: Dict[str, Dict[str, int]] = {}
    for x in exchanges:
        t = targets.setdefault(x.target, {"total": 0, "ng": 0})
        t["total"] += 1
        t["ng"] += 0 if x.answered else 1

    streaks: List[Dict[str, Any]] = []
    for target in sorted(targets):
        epochs = sorted(x.time for x in ng if x.target == target)
        for si, ei in find_time_streaks(epochs):
            streaks.append({
                "target": target,
                "start_epoch": epochs[si],
                "end_epoch": epochs[ei],
                "count": ei - si + 1,
                "duration_sec": round(epochs[ei] - epochs[si], 3),
            })
    streaks.sort(key=lambda s: s["start_epoch"])
    if len(streaks) > MAX_STREAKS:
        warnings.append(f"연속 손실 구간 {len(streaks)}곳 중 {MAX_STREAKS}곳만 기록")
        streaks = streaks[:MAX_STREAKS]

    total = len(exchanges)
    return {
        "total": total,
        "ok": total - len(ng),
        "ng": len(ng),
        "loss_pct": round(len(ng) * 100 / total, 2) if total else 0.0,
        "sender": sender,
        "targets": targets,
        "streaks": streaks,
        "ng_epochs": [x.time for x in ng][:MAX_NG_EPOCHS],
        "trailing_dropped": dropped,
        "warnings": warnings,
    }
