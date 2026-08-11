"""유선(포트 미러) pcap에서 ping ground truth를 만든다.

검증된 exping의 ICMP 추출·매칭 규칙(응답 인정 상한 1초)을 재사용한다 — 대시보드용
으로 EXPING xlsx 재현 규칙(RTT 정수 보정, 전각 문자열)은 쓰지 않고 Exchange 수준
에서 소비한다. docs/EXPING.md 참조.

sender 선정과 꼬리 무응답 판정은 EXPING 재구성(`exping.extract_exchanges`)과
다르게 동작한다 — 이 모듈만의 규칙이니 각 함수 docstring에 근거를 남긴다.
"""
import math
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import exping
from .ping_matching import find_time_streaks
from .timeparse import parse_local_epoch as _parse_local_epoch

#: streaks 항목 수 상한 — 비정상 캡처(수천 구간)로 결과 JSON이 비대해지는 것 방지
MAX_STREAKS = 100
#: ng_epochs 상한 — 타임라인 마커용 샘플
MAX_NG_EPOCHS = 1000

#: capinfos 실행 상한(초) — 이 안에서 0.2초 간격으로 취소를 폴링한다
_CAPINFOS_TIMEOUT_SEC = 30
_CAPINFOS_POLL_SEC = 0.2


def _rtt_stats(exchanges: List["exping.Exchange"]) -> Optional[Dict[str, Any]]:
    """응답 있는 exchange의 RTT 통계(ms). 응답 0건이면 None — 정직한 공백
    원칙(스펙 §1): 0이나 가짜 값으로 채우면 '무손실·0ms'로 오독된다.

    p95는 정렬 후 nearest-rank(ceil(0.95*n)-1 인덱스) — 외부 의존성 없이
    n=1에서도 안전하다.
    """
    rtts = sorted(x.rtt for x in exchanges if x.rtt is not None)
    if not rtts:
        return None
    n = len(rtts)
    p95 = rtts[max(0, math.ceil(0.95 * n) - 1)]
    return {
        "n": n,
        "min_ms": round(rtts[0] * 1000, 3),
        "avg_ms": round(sum(rtts) / n * 1000, 3),
        "max_ms": round(rtts[-1] * 1000, 3),
        "p95_ms": round(p95 * 1000, 3),
    }


def _filter_exchanges(
    exchanges: List["exping.Exchange"],
    sender: str,
    time_start: str,
    time_end: str,
    ip_filters: List[str],
    reply_timeout: float,
) -> Tuple[Optional[List["exping.Exchange"]], str, int]:
    """시간/IP 필터를 적용한다. 파싱 실패 시 (None, 에러메시지, 0)을 반환.

    ip_filters는 독립적인 필터 문자열들의 목록이다 — 사용자 ip_filter와
    mac_filter에서 유도된 derived_ip_filter가 각각 하나씩 들어올 수 있다(PR #22
    11라운드 — Finding A). 하나로 합쳐 교집합 IP 집합을 만드는 게 아니라, 각
    필터를 **순차적으로** 적용한다(AND of narrowing) — 필터마다 독립적으로
    "sender가 그 필터에 있으면 전체 유지, 아니면 target으로 좁히기" 판정을 하므로
    두 필터를 합집합으로 합치면 의미가 달라진다(예: user=target1, derived=sender
    자신의 IP인 직접 토폴로지 — 합치면 {target1, sender}가 되어 sender가 포함된
    필터 하나로 뭉개져 narrowing이 사라진다. 순차 적용이면 user 필터가 narrowing을
    맡고 derived 필터는 sender 포함이라 무해한 no-op이 된다).

    mac_filter는 유선(비-802.11) exchange에 MAC 개념이 없어 적용하지 않는다
    (호출부인 pipeline.py 주석 참조).

    time_end 경계 배제(반환값 세 번째 원소, boundary_excluded 건수, PR #22
    13라운드 — Codex P2, 보강): time_end가 요청과 그 응답 사이에 떨어지면, 유선은
    전체 캡처 기준 pairing이라 그 요청을 answered로 잡지만 무선 extract_frames는
    `frame.time < time_end`로 응답 프레임을 이미 잘라낸다 — 그러면 GT가 "무선이
    놓친 응답"을 인위적으로 만들어 손실률이 왜곡된다. `_drop_unreachable_tail`
    (capture_end 기준 물리적 꼬리 배제)과 같은 원리를 time_end에도 적용하되,
    **실제 응답 시각까지 정확히 본다**: `Exchange`는 응답 epoch을 별도 필드로
    저장하지 않지만 `rtt`가 "응답epoch − 요청epoch"이므로 `x.time + x.rtt`가 곧
    응답 epoch이다. 제외 조건은 `x.time + reply_timeout > end_epoch`(응답 창이
    time_end를 넘어갈 여지가 있음) **그리고** (`x.rtt is None`(무응답) **또는**
    `x.time + x.rtt >= end_epoch`(응답이 실제로 경계 밖)) — 둘 다 참이어야
    제외한다. 응답이 실제로 time_end **이전**에 왔다면(`x.time + x.rtt <
    end_epoch`) 무선도 그 응답 프레임을 본다(같은 `frame.time < time_end` 조건을
    통과하므로) — 이 경우까지 제외하면 무선은 matched인데 GT는 미포함이 되는
    **반대 방향** 1건 불일치가 새로 생긴다. 그래서 응답 창이 경계에 닿을 수
    있어도 실제 응답이 구간 안에 있으면 유지한다.

    time_start 쪽은 대칭 처리가 불필요하다: 요청이 start_epoch 이전이면 그
    exchange 자체가 이미 필터에서 빠진다(`x.time >= start_epoch` 요구, 아래) —
    무선도 그 요청 프레임을 아예 못 보므로(잘못된 요청 시각), 응답만 단독으로
    보이는 경우는 기존 "reply-only 관측 → 비교 불가" 처리(charts.js, 4~5라운드)가
    이미 정직하게 다룬다. 즉 이쪽은 두 필터가 "같은 요청을 아예 안 본다"는 점에서
    이미 대칭이라 별도 배제가 필요 없다.
    """
    out = exchanges
    boundary_excluded = 0
    if time_start:
        start_epoch = _parse_local_epoch(time_start)
        if start_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_start}", 0
        out = [x for x in out if x.time >= start_epoch]
    if time_end:
        end_epoch = _parse_local_epoch(time_end)
        if end_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_end}", 0
        out = [x for x in out if x.time < end_epoch]
        threshold = end_epoch - reply_timeout
        kept = []
        for x in out:
            near_boundary = x.time >= threshold
            # 응답이 실제로 경계 밖(또는 아예 없음)이어야 제외한다 — 응답이
            # time_end 이전에 왔다면 무선도 그 프레임을 보므로 배제하면 안 된다.
            # >=(inclusive): x.time == threshold(정확히 reply_timeout만큼 앞선
            # 요청)인 knife-edge에서 strict >였다면 이 게이트 자체를 건너뛰어
            # 버려, 응답이 마침 end_epoch에 정확히 걸치는 경우(무선 필터
            # `frame.time < time_end`는 그 프레임을 배제)까지 answered로 새어
            # 나갔다 — 무선의 배타적 `<`와 정확히 같은 경계에서 일치시킨다.
            response_outside = x.rtt is None or (x.time + x.rtt) >= end_epoch
            if near_boundary and response_outside:
                boundary_excluded += 1
                continue
            kept.append(x)
        out = kept
    for ip_filter in ip_filters:
        if not ip_filter:
            continue
        ips = {ip.strip() for ip in ip_filter.split(",") if ip.strip()}
        # 무선 'ip.addr == X'는 src/dst 어느 쪽이든 매칭. sender는 이 캡처의
        # 모든 exchange에서 고정 src이므로, sender가 필터에 있으면 전부
        # 매칭되는 것과 같다(=필터링 없음). 아니면 target(=dst)으로 좁힌다.
        if ips and sender not in ips:
            out = [x for x in out if x.target in ips]
    return out, "", boundary_excluded


def _cohort_requests(
    frames: List["exping.IcmpFrame"],
    time_start: str,
    time_end: str,
    ip_filters: List[str],
) -> Tuple[Optional[List["exping.IcmpFrame"]], str]:
    """echo request(icmp.type==8) 부분집합 — 시간 창·ip_filters로 좁힌 sender 후보군.

    sender는 "최다 요청 호스트"(exping.pick_sender)로 고르되, **전체 pcap이 아니라
    이 부분집합에서** 고른다. 전체에서 고르면(기존 extract_exchanges 방식) 배경
    호스트가 필터 구간 밖에서 sender보다 훨씬 많이 ping을 보냈을 때 그 배경 호스트가
    잘못 선택된다 — 필터가 있어도 무시된 채 전체 pcap 기준으로 sender가 확정되기
    때문이다.

    ip_filters의 각 원소는 여기서도 무선 쪽과 같은 tshark `ip.addr == X`대칭(src/dst
    어느 쪽이든 매칭)을 쓴다 — sender 자신의 IP를 몰라도, "이 IP가 요청의 src거나
    dst다"라는 조건은 성립한다. src만 보면 target IP만 준 필터(예: "이 target에
    ping하는 sender를 찾아라")가 코호트를 비워 에러를 내는데, 그건 무선 필터
    의미와도 어긋난다. dst까지 보면 그 경우도 "이 target에 ping한 요청들"이
    코호트가 되고 pick_sender가 그 요청들의 최다 송신자를 sender로 고른다 —
    이후 exchange 수준 `_filter_exchanges`(sender가 필터에 있으면 전체 유지,
    아니면 target 좁히기)가 최종 표시 범위를 정리한다.

    ip_filters는 사용자 ip_filter와 mac_filter에서 유도된 derived_ip_filter가
    각각 하나씩 들어올 수 있는 목록이다(PR #22 11라운드 — Finding A) — 각 필터를
    독립적으로 "src 또는 dst가 이 필터 집합에 있어야 한다"고 요구하므로 결과는
    필터들의 AND(교집합)다. `_filter_exchanges`와 같은 이유로 하나의 합집합
    IP 집합으로 합치지 않는다(호출부 `build_ground_truth` 주석 참조).

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
    ip_sets = [
        {ip.strip() for ip in f.split(",") if ip.strip()}
        for f in ip_filters if f
    ]

    cohort = []
    for f in frames:
        epoch, src, dst, typ, *_rest = f  # IcmpFrame은 tuple 별칭(namedtuple 아님)
        if typ != exping.ICMP_ECHO_REQUEST:
            continue
        if start_epoch is not None and epoch < start_epoch:
            continue
        if end_epoch is not None and epoch >= end_epoch:
            continue
        if any(src not in ips and dst not in ips for ips in ip_sets):
            continue
        cohort.append(f)
    return cohort, ""


def _detect_capture_end(
    pcap_path: str, tshark_path: str, cancel_event: Optional[Any] = None
) -> Optional[float]:
    """capinfos로 실제 캡처의 마지막 패킷 시각(epoch)을 구한다. 실패/부재 시 None.

    cancel_event가 이미 set이면 capinfos를 **띄우지 않고** None을 반환한다 — 취소를
    보고한 뒤 자식 프로세스가 하나 더 생기지 않게. 실행 **중에** 들어온 취소도
    0.2초 간격 폴링으로 감지해 terminate(→ 5초 안에 안 죽으면 kill) 후 None을
    반환한다 — subprocess.run(timeout=30)은 취소가 set돼도 프로세스가 끝날 때까지
    최대 30초 블록해 /api/cancel이 성공을 보고한 뒤에도 자식이 한동안 남는다.

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
    if cancel_event is not None and cancel_event.is_set():
        return None
    candidates = []
    if tshark_path:
        # Windows에서는 tshark.exe 옆에 capinfos.exe가 있다 — 접미사 없는 "capinfos"만
        # 보면 형제 탐색이 항상 실패해 PATH 폴백(또는 캡처 끝 미확인)으로 떨어진다.
        candidates.append(
            str(Path(tshark_path).parent / ("capinfos" + Path(tshark_path).suffix))
        )
    found = shutil.which("capinfos")
    if found:
        candidates.append(found)
    capinfos_path = next((c for c in candidates if c and Path(c).exists()), None)
    if not capinfos_path:
        return None
    try:
        proc = subprocess.Popen(
            [capinfos_path, "-e", "-S", "-M", str(pcap_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except OSError:
        return None
    deadline = time.monotonic() + _CAPINFOS_TIMEOUT_SEC
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                return None
            try:
                # communicate(timeout=)을 반복 호출하면 매 호출이 내부 버퍼 상태에
                # 의존해 재읽기 우려가 있다 — wait()로만 폴링하고(파이프를 건드리지
                # 않음), 프로세스가 끝난 뒤 communicate()를 단 한 번만 호출해 전체
                # 출력을 한 번에 읽는다. capinfos 출력은 헤더 요약 몇 줄뿐이라 파이프
                # 버퍼가 찰 위험은 없다.
                proc.wait(timeout=_CAPINFOS_POLL_SEC)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    proc.kill()
                    proc.wait()
                    return None
                continue
        stdout, _stderr = proc.communicate()
    except (OSError, ValueError):
        proc.kill()
        proc.wait()
        return None
    if proc.returncode != 0:
        return None
    for line in (stdout or "").splitlines():
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


def _unverified_unanswered_count(
    exchanges: List["exping.Exchange"],
    frames: List["exping.IcmpFrame"],
    reply_timeout: float,
) -> int:
    """캡처 끝 시각 미확인 시 "응답 기회를 검증 못 한" 무응답 수 — 제거하지 않고
    세기만 한다.

    이전 규칙("마지막 응답 뒤에 붙은 연속 무응답")은 리스트 위치 기준이라 회전
    다중 target 캡처(무응답 A 뒤에 **다른** target의 응답 B가 리스트 마지막에
    옴)에서 A를 놓친다 — A가 마지막이 아니라는 이유만으로 "꼬리"가 아니라고
    판단하지만, A의 응답 창이 캡처 끝에서 잘렸을 가능성은 위치와 무관하다.

    대신 시각 기준으로 판정한다: L = 관측된 전체 ICMP 프레임(frames, cohort/필터
    적용 전 — 이 시점엔 아직 전체 캡처 기준)의 최대 epoch(캡처 끝의 근사). 무응답
    요청 x가 `x.time + reply_timeout >= L`이면 그 응답 창이 L(캡처가 실제로 어디까지
    이어졌는지 아는 마지막 지점)에 닿거나 넘어가므로 "응답이 왔었을 수도, 캡처가
    먼저 끝났을 수도" 있어 검증 불가다 — 경계(정확히 L에서 창이 닫히는 경우)는
    "캡처가 그 순간 끝났을 수도 있다"는 불확실성이 여전히 남아 있어 안전한 쪽
    (검증 불가로 간주)을 택한다. `x.time + reply_timeout < L`이면 그 창이 캡처
    안에서 완전히 닫힌 뒤에도 응답이 없었으므로 확정 손실 — 경고 대상이 아니다
    (과대 계상 우려 자체가 없다).
    """
    if not frames:
        return 0
    # IcmpFrame은 tuple 별칭(namedtuple 아님) — 첫 필드(epoch)만 필요하므로 언패킹.
    latest = max(epoch for epoch, *_rest in frames)
    return sum(1 for x in exchanges if not x.answered and x.time + reply_timeout >= latest)


def build_ground_truth(
    pcap_path: str,
    tshark_path: str = "tshark",
    reply_timeout: float = exping.DEFAULT_REPLY_TIMEOUT,
    time_start: str = "",
    time_end: str = "",
    ip_filter: str = "",
    derived_ip_filter: str = "",
    cancel_event: Optional[Any] = None,
) -> Dict[str, Any]:
    """유선 pcap → ping ground truth dict. 실패 시 {"error": str, "warnings": [...]}.

    time_start/time_end/ip_filter는 무선 extract_frames()가 받는 동일 인자와
    같은 구간을 가리키도록 대칭으로 구현했다 — 서로 다른 구간을 비교하지 않기
    위함(무선 필터만 적용되고 유선은 전체 구간을 쓰면 손실률이 왜곡된다).

    ip_filter(사용자가 명시)와 derived_ip_filter(pipeline이 mac_filter에서 유도한
    값)는 **독립적으로 순차 적용**돼 AND로 결합된다(PR #22 11라운드 — Finding A).
    하나로 합쳐 버리면(예: 두 값을 합집합 IP 집합으로 만들어 한 번만 필터링) 직접
    토폴로지 + 명시 target 필터에서 사용자의 narrowing이 사라진다 — mac_filter
    대상 STA가 sender 자신인 직접 토폴로지에서는 derived_ip_filter가 sender
    자신의 IP이므로, 합집합에 sender IP가 섞이는 순간 "sender가 필터에 있으면
    전체 유지" 규칙이 발동해 사용자가 명시한 target 좁히기가 무력화된다. 반면
    두 필터를 각각 독립적으로 적용하면: 사용자 필터가 narrowing을 맡고(그 필터
    집합에 sender가 없으므로), derived 필터는 sender를 포함해 no-op이 되어 무해
    하다 — 두 토폴로지(직접/상류) 모두에서 항상 옳다(자세한 근거는 `_cohort_requests`·
    `_filter_exchanges` docstring 참조). ip_filter만 있고 derived_ip_filter가
    없으면(mac_filter 미사용) 10라운드 이전과 동일하게 동작한다.

    처리 순서: ① 필터가 적용된 부분집합("코호트")에서 sender 선정(_cohort_requests)
    ② 무선 캡처 가드 ③ 전체 캡처 기준 요청↔응답 짝짓기(exping.pair_exchanges)
    ④ 캡처 끝이 **capinfos로 확인된 경우에만** 물리적 꼬리 제거(_drop_unreachable_tail)
    ⑤ 시간/IP 필터로 최종 표시 구간 좁히기 + **time_end 경계 요청 배제**
    (_filter_exchanges) ⑥ 집계. ③이 필터 이전(전체 캡처 기준)인 이유: 창 끝
    근처 요청의 응답이 창 밖(그러나 캡처 안)에 있어도 매칭돼야 한다. ④가 ⑤보다
    먼저인 이유: 필터로 창을 먼저 자르면 창 안 마지막 자리의 진짜 손실이 물리적
    꼬리로 오인될 수 있다(trailing_dropped는 항상 물리적 꼬리 기준). 캡처 끝이
    미확인이면 ④를 건너뛰고(drop 0건) 응답 기회를 검증하지 못한 무응답
    (_unverified_unanswered_count)을 손실로 집계한 뒤 과대 계상 가능성을
    warnings로 알린다.

    time_end 경계 배제(PR #22 13라운드, 보강): time_end가 요청↔응답 사이에
    떨어지면 무선 extract_frames는 응답 프레임을 이미 잘라내는데(frame.time <
    time_end) 유선은 전체 캡처 pairing이라 그대로 answered로 잡는다 — 그러면
    GT가 무선이 볼 수 없는 응답을 근거로 "무선 손실 없음"을 주장하게 돼 두 쪽이
    다른 모집단을 비교한다. _filter_exchanges가 응답 창(reply_timeout)이
    time_end를 넘어갈 여지가 있는 요청 중, **실제 응답도 경계 밖(또는 무응답)인
    것만** 제외하고(x.time + x.rtt로 정확한 응답 시각을 판정 — 응답이 실제로
    time_end 이전에 왔으면 무선도 그 프레임을 보므로 유지) boundary_excluded
    건수를 warnings로 알린다(④의 capinfos 기준 물리적 꼬리 배제와 같은 원리를
    time_end에 적용한 것). time_start 쪽은 대칭 배제가 불필요하다 — 그 경계의
    요청은 애초에 필터에서 빠져(x.time >= start_epoch) 유선·무선 양쪽 다 "이
    요청을 안 본다"는 점에서 이미 일치한다(자세한 근거는 _filter_exchanges
    docstring 참조).

    cancel_event(threading.Event)를 주면 추출 중 취소가 자식 tshark까지 전파되고
    (exping.extract_icmp_frames), 그때는 error가 아니라 {"cancelled": True}를
    반환한다 — 호출부(pipeline)가 전체 분석 취소와 같은 방식으로 처리하도록.
    추출이 끝난 뒤 들어온 취소는 capinfos(_detect_capture_end)를 띄우기 직전과,
    capinfos 실행이 끝난 직후(폴링 루프가 취소로 None을 반환했을 수 있어 "캡처 끝
    미확인"과 구분하기 위해)에도 확인해 같은 값을 반환한다.
    """
    warnings: List[str] = []
    # 추출 경고만 담는 **전용** 리스트. 공용 warnings를 그대로 넘기면
    # `extraction_partial = bool(warnings)`가 "이 줄 이전에 다른 경고가 추가되지
    # 않는다"는 암묵적 순서 계약에 의존하게 된다 — 나중에 누가 무관한 정보성
    # 경고를 앞에 넣으면 정상 추출이 부분 실패로 오인돼 유선 GT가 판정에서
    # 통째로 빠진다(조용히, 아무도 모르게). 리스트를 분리하면 구조적으로 막힌다.
    extract_warnings: List[str] = []
    try:
        # warnings_out: tshark가 일부 행만 내고 비정상 종료한 경우의 경고를 gt
        # warnings로 올린다 — stderr만으로는 웹 경로가 알 수 없어 잘린 pcap이
        # 경고 없는 "성공한 GT"로 게시된다(손실 과소 계상).
        frames = exping.extract_icmp_frames(
            pcap_path, tshark=tshark_path, cancel_event=cancel_event,
            warnings_out=extract_warnings,
        )
    except InterruptedError:
        return {"cancelled": True}
    except FileNotFoundError:
        return {"error": f"tshark 를 찾을 수 없다: {tshark_path}",
                "warnings": warnings + extract_warnings}
    except (ValueError, TimeoutError) as exc:
        return {"error": str(exc), "warnings": warnings + extract_warnings}
    warnings.extend(extract_warnings)

    # **추출 무결성 플래그.** 전용 리스트만 보므로 이후 어떤 경고가 추가돼도
    # 영향받지 않는다.
    #
    # 부분 실패면 손실률이 **실제보다 낮게** 나온다(못 읽은 요청은 애초에 모집단에
    # 없다). 그 값을 1차 판정으로 승격하면 건강도가 부풀고 진짜 손실 이슈가 눌린다
    # — 소비자(`structured._loss_for_judgment`)가 이 플래그로 걸러낸다.
    # `error`가 아니라 플래그인 이유: 화면의 GT 카드는 부분 결과라도 보여줄 값이
    # 있고, "판정에 못 쓴다"와 "아예 없다"는 다르다.
    extraction_partial = bool(extract_warnings)

    # ip_filter(사용자)와 derived_ip_filter(mac_filter 유도값)는 독립적인 필터로
    # 순차 AND 적용된다 — 위 build_ground_truth docstring·_cohort_requests
    # docstring 근거 참조.
    ip_filters = [ip_filter, derived_ip_filter]
    has_ip_filter = bool(ip_filter or derived_ip_filter)

    cohort, err = _cohort_requests(frames, time_start, time_end, ip_filters)
    if cohort is None:
        return {"error": err, "warnings": warnings}
    if not cohort:
        if time_start or time_end or has_ip_filter:
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

    # capinfos 자식을 띄우기 전 마지막 취소 확인 — 추출·짝짓기 도중 들어온 취소가
    # 여기서 걸린다(취소를 보고해 놓고 자식이 또 하나 도는 일을 막는다).
    if cancel_event is not None and cancel_event.is_set():
        return {"cancelled": True}

    capture_end = _detect_capture_end(pcap_path, tshark_path, cancel_event)
    # capinfos 실행 도중 취소되면 _detect_capture_end는 (여러 다른 실패 사유와
    # 구분 없이) None을 반환한다 — 그 None을 "캡처 끝 미확인"으로 오인해 이후
    # streak 구성까지 진행하면 취소를 무시한 채 부분 결과가 게시된다. 폴링 루프가
    # 취소 때문에 None을 반환했다면 이 시점에 cancel_event가 set돼 있으므로 여기서
    # 걸러낸다(PR #22 11라운드 — Finding B).
    if cancel_event is not None and cancel_event.is_set():
        return {"cancelled": True}
    if capture_end is None:
        # 검증된 물리적 끝이 없으면 **아무것도 지우지 않는다**. ICMP 마지막 프레임을
        # 프록시로 쓰면 임계값이 실제 캡처 끝보다 앞당겨져(뒤에 non-ICMP 트래픽이
        # 더 있는 캡처) 진짜 손실까지 조용히 지워진다 — 특히 마지막 ICMP 프레임
        # 자체가 손실된 요청인 경우. 손실을 숨기는 쪽보다 남겨 두고 과대 계상
        # 가능성을 경고하는 쪽이 안전하다(사용자가 캡처를 보고 판단할 수 있다).
        dropped = 0
        unverified = _unverified_unanswered_count(exchanges, frames, reply_timeout)
        if unverified:
            warnings.append(
                f"캡처 끝 시각 미확인 — 응답 기회를 검증하지 못한 무응답 {unverified}건을 "
                "손실로 집계 (캡처가 응답보다 먼저 끊긴 경우 손실률이 과대 계상될 수 있음)"
            )
    else:
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

    if time_start or time_end or has_ip_filter:
        filtered, err, boundary_excluded = _filter_exchanges(
            exchanges, sender, time_start, time_end, ip_filters, reply_timeout
        )
        if filtered is None:
            return {"error": err, "warnings": warnings}
        exchanges = filtered
        if boundary_excluded:
            warnings.append(
                f"구간 끝 경계 요청 {boundary_excluded}건 제외 — 응답 창"
                f"(±{reply_timeout}s)이 time_end를 넘어 무선과 동일 조건 비교 불가"
            )
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
    result: Dict[str, Any] = {
        "total": total,
        "ok": total - len(ng),
        "ng": len(ng),
        "loss_pct": round(len(ng) * 100 / total, 2) if total else 0.0,
        "sender": sender,
        "targets": targets,
        "streaks": streaks,
        "ng_epochs": [x.time for x in ng][:MAX_NG_EPOCHS],
        "trailing_dropped": dropped,
        # True면 tshark 부분 실패로 모집단이 불완전하다 — 손실률이 과소 계상이라
        # 판정 근거로 쓰면 안 된다(표시는 가능).
        "extraction_partial": extraction_partial,
        "warnings": warnings,
    }
    # 유선 RTT 1차 노출(스펙 2026-08-05-wired-rtt-primary §1): exchanges는
    # 위 손실 집계와 정확히 같은 최종 모집단이다 — 시간창·필터·꼬리 제외가
    # 모두 반영된 뒤의 리스트라 total == len(exchanges)가 항상 성립한다.
    result["exchanges"] = [
        {"epoch": x.time, "target": x.target,
         "rtt_ms": round(x.rtt * 1000, 3) if x.rtt is not None else None}
        for x in exchanges
    ]
    rtt_stats = _rtt_stats(exchanges)
    if rtt_stats is not None:
        result["rtt_stats"] = rtt_stats
    if time_end:
        # 13라운드의 경계 배제(_filter_exchanges: 응답 창이 time_end를 넘어갈
        # 여지가 있고 실제 응답도 경계 밖인 요청 제외)는 유선 GT에만 적용됐다 —
        # 무선 full_list에는 그 요청이 그대로 loss로 남는다(요청은 창 안, 응답만
        # tshark의 frame.time < time_end에 잘림). GT 카드(charts.js)가 같은
        # 술어를 무선 비교에도 미러링할 수 있도록 컷오프 값을 노출한다(PR #22
        # 14라운드 — Finding B). 이 지점에 도달했다는 건 time_end가 이미
        # 성공적으로 파싱됐다는 뜻이다(파싱 실패는 위 _filter_exchanges 호출에서
        # 먼저 에러로 반환된다).
        result["boundary_cutoff_epoch"] = _parse_local_epoch(time_end) - reply_timeout
    return result
