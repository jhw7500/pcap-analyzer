"""다중 무선 캡처의 시계 정렬과 중복 제거.

같은 채널을 두 위치에서 캡처하면 같은 802.11 프레임이 양쪽에 잡힌다. 비콘의
TSF(wlan.fixed.timestamp)는 AP가 프레임에 찍는 값이라 어느 캡처에서 봐도
동일하다 — (BSSID, TSF) 정확 일치 쌍의 epoch 차 중앙값이 곧 캡처 간 시계
오프셋이다. 실측(2026-07-21 TEST1, DFK↔cantops): 12,298쌍, 오프셋 +183.510s,
IQR 3.4ms — 사전 timesync 보정 없이도 무선 간 정렬이 가능함을 확인했다.

TSF 폴백((TA, seq, subtype) 매칭)은 ±5초 창을 쓰므로 사전 보정된 입력을
전제한다(스펙 §3). 그것도 실패하면 오프셋 0 + 경고.
"""
import bisect
import datetime as dt
import statistics
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Frame

MERGE_MIN_TSF_PAIRS = 10
FALLBACK_MATCH_WINDOW_SEC = 5.0
MERGE_DEDUP_WINDOW_SEC = 0.05  # Task 3에서 사용
# 창 안 후보 초과 시 낡은 순으로 매칭 후보에서 제외 — 최근접 매칭 원칙과 정합(먼
# 후보일수록 옳은 짝일 확률 낮음), same-source 밀집 버스트의 무한 누적을 막는다.
MERGE_MAX_LIVE_GROUPS = 64


@dataclass
class OffsetResult:
    offset_sec: float
    method: str
    pairs: int
    spread_sec: float
    warnings: List[str] = field(default_factory=list)


def _tsf_table(frames: List[Frame]) -> Dict[Tuple[str, int], float]:
    """(BSSID, TSF) → epoch 매핑.

    같은 캡처 안에서 같은 키가 서로 다른 epoch로 두 번 이상 등장하면 어느
    발생이 진짜 짝인지 알 수 없다 — 마지막 값으로 덮어쓰면(기존 동작) 잘못된
    epoch가 섞여 오프셋 중앙값을 오염시킬 수 있다. 재등장한 키는 테이블에서
    아예 제외해 모호한 매칭을 원천 차단한다(PR #23 리뷰 2라운드 Finding E-1).
    """
    out: Dict[Tuple[str, int], float] = {}
    dupes: set = set()
    for f in frames:
        if f.subtype != "8" or not f.bssid or not f.tsf:
            continue
        try:
            key = (f.bssid, int(f.tsf))
        except ValueError:
            continue  # 비정상 TSF 값은 무시
        if key in dupes:
            continue
        if key in out:
            del out[key]
            dupes.add(key)
            continue
        out[key] = f.epoch
    return out


def _median_iqr(diffs: List[float]) -> Tuple[float, float]:
    s = sorted(diffs)
    n = len(s)
    return statistics.median(s), (s[(3 * n) // 4] - s[n // 4] if n >= 4 else 0.0)


def _ref_candidates_in_window(
    sorted_ref: List[Tuple[int, float]], sorted_ref_epochs: List[float], query_epoch: float,
) -> List[Tuple[int, float]]:
    """query_epoch ± FALLBACK_MATCH_WINDOW_SEC 창 안의 (원본 인덱스, epoch) 쌍만
    bisect로 열거한다.

    sorted_ref는 epoch 기준 정렬된 (원본 리스트 인덱스, epoch) 쌍, sorted_ref_epochs는
    그 epoch만 뽑은 병렬 리스트(bisect 검색용)다. 창 밖 ref 발생은 아예 순회하지
    않으므로 반환 개수는 ref 전체 개수가 아니라 "그 창 안에 실제로 존재하는
    개수"로 bound된다 — seq 랩(12비트, 4096마다 재사용)으로 같은 키가 대량
    캡처에서 밀집 등장해도 후보 생성이 창 크기로 제한된다(PR #23 리뷰 4라운드
    Finding A). 원본 인덱스를 함께 반환하는 이유: "그 ref 발생 자체"를 소비
    추적해야 하기 때문 — 같은 epoch를 가진 서로 다른 ref 발생(이론상 가능)을
    값(epoch)만으로 구분하면 서로 다른 발생을 하나로 오인해 재사용을 막지
    못할 수 있다.

    기존 `abs(d) <= FALLBACK_MATCH_WINDOW_SEC` 필터와 **정확히 동치는 아니다** —
    부동소수 경계(정확히 ±5.0s)에서는 기존 필터의 안전 방향 superset이다(후보가
    더 포함될 수는 있어도 누락되지는 않는다: `lo`/`hi`는 각각
    `query_epoch - window`/`query_epoch + window`를 한 번 계산해 비교하는 반면
    기존 코드는 `ref_epoch - of.epoch`를 계산해 비교해, 두 계산 순서가 부동소수
    반올림에서 완전히 같은 결과를 보장하지 않는다 — 경계에 걸친 극소수 사례에서
    이쪽이 아주 살짝 더 포함시킬 수는 있어도 절대 빠뜨리지는 않는다). 랜덤
    epoch·창 경계 근접값으로 2만회 퍼징해 "필터 후보 집합 ⊆ bisect 후보 집합"
    불변식을 확인했다(리뷰 재검증 완료 — PR #23 리뷰 4라운드 재리뷰).
    """
    lo = bisect.bisect_left(sorted_ref_epochs, query_epoch - FALLBACK_MATCH_WINDOW_SEC)
    hi = bisect.bisect_right(sorted_ref_epochs, query_epoch + FALLBACK_MATCH_WINDOW_SEC)
    return sorted_ref[lo:hi]


def estimate_offset(reference: List[Frame], other: List[Frame]) -> OffsetResult:
    """other의 epoch에 더하면 reference 타임라인이 되는 오프셋을 추정한다."""
    ref_t, oth_t = _tsf_table(reference), _tsf_table(other)
    common = set(ref_t) & set(oth_t)
    if len(common) >= MERGE_MIN_TSF_PAIRS:
        med, iqr = _median_iqr([ref_t[k] - oth_t[k] for k in common])
        return OffsetResult(med, "tsf", len(common), iqr)

    # 폴백: (TA, seq, subtype) 매칭 — 사전 보정 전제의 ±5초 창. seq는 랩어라운드
    # (12비트, 4096마다 재사용)되므로 같은 키가 창 안에 두 번 이상 등장할 수
    # 있다 — 창 안 첫 후보를 그대로 취하면(최선착) 더 먼 쪽에 잘못 걸려 실제
    # 오프셋이 몇 초 어긋난 값으로 붕괴할 수 있다. 키별로 (ref 발생, other
    # 프레임) 후보 쌍을 모아 |diff| 최근접 순으로 그리디 매칭하고, 매칭된 ref
    # 발생·other 프레임은 각각 한 번만 소비한다(1:1 — PR #23 리뷰 Finding C).
    # 후보 열거는 bisect로 창 안만 순회한다 — 키별 전 조합(len(ref)×len(other))을
    # 열거하면 밀집 키가 생기는 대량 캡처(예: 백만 프레임)에서 O(N²/4096)로
    # 행업·메모리 고갈을 일으킨다(PR #23 리뷰 4라운드 Finding A).
    # abs_d가 완전히 동률이고 그 순간 두 후보가 서로 다른 (ri, oi)를 두고
    # 자원 충돌(같은 ref 또는 같은 other를 두고 경쟁)하면, list.sort()가
    # 안정 정렬이라 삽입 순서(딕셔너리·리스트 순회 순서)에 따라 최종 선택이
    # 달라질 수 있다 — 다만 실제 tshark epoch는 µs 정밀도(frame.time_epoch가
    # 마이크로초 단위 소수)라 서로 다른 두 프레임이 같은 ref까지의 거리를
    # 소수점 이하까지 완전히 동일하게 갖는 경우는 사실상 도달 불가하다.
    ref_keys: Dict[Tuple[str, str, str], List[float]] = {}
    for f in reference:
        if f.ta and f.seq:
            ref_keys.setdefault((f.ta, f.seq, f.subtype), []).append(f.epoch)
    other_keys: Dict[Tuple[str, str, str], List[Frame]] = {}
    for f in other:
        if f.ta and f.seq:
            other_keys.setdefault((f.ta, f.seq, f.subtype), []).append(f)

    diffs: List[float] = []
    for key, other_frames in other_keys.items():
        ref_epochs = ref_keys.get(key)
        if not ref_epochs:
            continue
        sorted_ref = sorted(enumerate(ref_epochs), key=lambda p: p[1])
        sorted_ref_epochs = [e for _, e in sorted_ref]
        candidates = []
        for oi, of in enumerate(other_frames):
            for ri, ref_epoch in _ref_candidates_in_window(sorted_ref, sorted_ref_epochs, of.epoch):
                d = ref_epoch - of.epoch
                candidates.append((abs(d), ri, oi, d))
        candidates.sort(key=lambda c: c[0])
        used_ref: set = set()
        used_other: set = set()
        for _, ri, oi, d in candidates:
            if ri in used_ref or oi in used_other:
                continue
            used_ref.add(ri)
            used_other.add(oi)
            diffs.append(d)
    if len(diffs) >= MERGE_MIN_TSF_PAIRS:
        med, iqr = _median_iqr(diffs)
        return OffsetResult(med, "seq-fallback", len(diffs), iqr)

    return OffsetResult(
        0.0, "none", 0, 0.0,
        warnings=["캡처 간 오프셋을 추정하지 못해 0으로 가정 — 타임라인이 어긋날 수 있다 "
                  "(비콘 TSF 쌍 부족·공통 프레임 없음)"],
    )


@dataclass
class MergeResult:
    frames: List[Frame]                 # 통합·정렬·재번호된 리스트 (기존 파이프라인 입력)
    # 계약(TL;DR, PR #23 리뷰 8라운드 Finding C — 3단계 착수자용, 아래 상세
    # 설명과 중복되더라도 필드 선언부에서 바로 보이는 게 목적): 이 Frame
    # 객체들은 `frames`(대표로 뽑힌 그룹)와 **인스턴스를 공유**하고
    # `_merge_decoded_fields` 등에 의해 **in-place로 변경**될 수 있다 — 그
    # 소스만의 순수 원본이 필요하면 `merge_captures` 호출 **전에** 프레임을
    # `copy.deepcopy`로 스냅샷 떠 두어라.
    #
    # 소스별 원본(epoch 보정됨) — 3단계용. 여기 담긴 Frame 객체는 `frames`
    # (대표로 뽑힌 그룹)와 **동일 인스턴스를 공유**한다 — 이 공유가 두 가지
    # 결과를 낳는다:
    #
    # (해소, PR #23 리뷰 6라운드 Finding B) 번호 복원: `frames` 조립 시
    # 대표는 통합 타임라인 순번으로 재번호된다(`f.number = i + 1`) — 그
    # 순간 원본 tshark frame.number가 지워지면 per_source로 "이 대표가
    # 원래 그 소스에서 몇 번이었는지" 역추적할 수 없었다. 재번호 직전에
    # `Frame.orig_number`에 원본 값을 스탬프하므로, per_source의 대표
    # 프레임에서 원본 번호가 필요하면 `f.orig_number or f.number`를 쓴다
    # (`orig_number == 0`이면 재번호가 아예 없었다는 뜻이라 `number`가 곧
    # 원본이다 — 단일 소스, 또는 이 그룹의 비-대표 프레임).
    #
    # (미해소, 잠재 지뢰 — PR #23 리뷰 4라운드 재리뷰) 필드 차용 오염:
    # `_merge_decoded_fields`가 대표 프레임을 제자리 mutate하므로, 어떤
    # 소스의 프레임이 dedup 그룹의 대표가 되면 그 소스가 실제로 복호화하지
    # 못한 필드값을 **다른 소스에서 빌려와** 채운 채로 per_source에도
    # 남는다. per_source를 "그 소스가 직접 관측·복호화한 원본"으로
    # 소비하려면(예: 소스별 복호화율 집계) 병합 전 스냅샷이 필요하다 —
    # 현재는 그런 소비자가 없어 문제로 드러나지 않았을 뿐이다.
    per_source: Dict[str, List[Frame]]
    offsets: Dict[str, OffsetResult]    # 소스 태그 → 추정 결과 (기준 w1 제외)
    stats: Dict[str, Any]
    warnings: List[str]


def _dedup_key(f: Frame) -> Tuple:
    """dedup 매칭 키. seq가 있으면 (TA, seq, subtype, retry) 정확 매칭.

    제어 프레임(ACK 등)은 seq가 없어 (subtype, TA 또는 RA, retry)로 근사한다 —
    같은 상대와 주고받는 동일 subtype 제어 프레임끼리는 구분하지 못하는 한계가
    있지만, 창(MERGE_DEDUP_WINDOW_SEC)이 좁아 실측 트래픽에서는 충분한 근사다.
    """
    if f.seq:
        return ("s", f.ta, f.seq, f.subtype, f.retry)
    return ("c", f.subtype, f.ta or f.ra, f.retry)


def _decoded_score(f: Frame) -> int:
    """프레임이 복호화됐다는 지표를 **개수**로 센다 — 다운스트림 판정(is_icmp_*,
    is_arp, is_pure_tcp_ack 등)에 실제로 쓰이는 복호화 필드 전수: ip_src(IP
    페이로드) · arp_opcode(ARP) · icmp_type(ICMP) · eapol_msgnr(EAPOL 4-way) ·
    tcp_flags(TCP) · tcp_len(TCP 페이로드 길이 — is_pure_tcp_ack가
    `tcp_len=="0"`을 요구) 중 채워진 필드 수.

    bool로만 판정하면(1라운드 수정) 지표가 하나라도 있는 두 사본이 항상
    동률로 취급돼, 필드를 더 많이 보존한 완전한 사본(예: ip_src+icmp_type)이
    부분적으로만 복호화된 사본(예: ip_src만)에 "이른 epoch" 동률 규칙으로 질
    수 있다 — 더 많은 정보를 보존한 사본이 대표가 돼야 한다(PR #23 리뷰
    2라운드 Finding D). tcp_len 누락 시 ip_src+tcp_flags 동률에서 tcp_len까지
    가진 완전판이 지는 동일한 문제가 재현된다(PR #23 리뷰 3라운드 Finding B).
    tcp_len="0"도 `bool("0")`이 True이므로 정상적으로 "채워짐"으로 계산된다.
    """
    return sum(
        bool(x) for x in (
            f.ip_src, f.arp_opcode, f.icmp_type, f.eapol_msgnr, f.tcp_flags, f.tcp_len,
        )
    )


def _prefer_new_representative(rep: Frame, candidate: Frame) -> bool:
    """대표 교체 여부 판정: 복호화 지표(_decoded_score) 점수가 높은 쪽 우선,
    동률이면 이른 epoch 우선.

    실측 근거: DFK 캡처는 완전 암호화(ICMP 0건)라 "먼저 잡힌 쪽"을 그대로 대표로
    쓰면 ping 분석에 쓸 IP 필드가 소실된다 — 복호화된 사본이 있으면 그쪽을 대표로.

    이 함수는 대표 "정체성"만 정한다 — 개별 필드 채움은 `_merge_decoded_fields`가
    별도로 맡는다(PR #23 리뷰 4라운드 Finding B). `_decoded_score`가 보는
    필드(ip_src·arp_opcode·icmp_type·eapol_msgnr·tcp_flags·tcp_len)만 같으면
    동률로 판정되는데, 그 목록에 없는 필드(ip_dst·icmp_seq·icmp_ident 등)는
    한쪽에만 있어도 점수에 반영되지 않아 대표 선정만으로는 소실될 수 있다.
    """
    rep_score, cand_score = _decoded_score(rep), _decoded_score(candidate)
    if cand_score != rep_score:
        return cand_score > rep_score
    return candidate.epoch < rep.epoch


#: === Frame 필드 전수 분류(PR #23 리뷰 5라운드 — 재발 방지용 완결 스윕) ===
#: 매 라운드 새 결손 필드가 나올 때마다 allowlist에 하나씩 추가하는 패턴을
#: 끝내기 위해 Frame의 전체 필드를 3분류했다. (a)에 속하는데 아래
#: _MERGEABLE_DECODED_FIELDS·_merge_protocol_field에 없는 필드가 새로
#: 발견되면 이 표부터 갱신할 것 — fix report에도 동일 표를 남긴다.
#:
#: (a) 복호화 유래 + 다운스트림 소비 → 병합 대상.
#:   ip_src/ip_dst          — ping_matching.build_ping_matches의 IP 흐름 매칭
#:   icmp_type/icmp_seq/icmp_ident — build_ping_matches의 ICMP 요청/응답 짝짓기
#:   arp_opcode             — Frame.is_arp, control_traffic.py·evidence.py ARP 판정
#:   tcp_len/tcp_flags       — Frame.is_pure_tcp_ack(제어 트래픽 판정)
#:   eapol_msgnr             — eapol.build_handshakes 4-way 메시지 번호
#:   current_ap              — web/structured.py _structured_roaming의 직전 AP·
#:                             밴드 전환 판정(PR #23 리뷰 5라운드 신규)
#:   reason_code              — web/frame_table.py 디버그 프레임 표의 Deauth/
#:                             Disassoc 사유 코드(PR #23 리뷰 5라운드 신규)
#:   protocol                — **별도 규칙**(_merge_protocol_field, 아래) 필요:
#:                             "빈 문자열"이 아니라 "802.11"(tshark가 802.11
#:                             계층까지만 해석했다는 포괄값)이 결손 상태라
#:                             단순 채움 규칙(빈 값만 채움)으로는 못 잡는다.
#:                             Frame.is_roaming_related(protocol=="EAPOL" 검사
#:                             — EAPOL 데이터 프레임은 subtype이 QoS Data와
#:                             같은 "40"이라 subtype만으로는 못 가려낸다)·
#:                             web/structured.py proto_counts·
#:                             core/modules/overview.py proto_counts·
#:                             core/modules/control_traffic.py 표시·
#:                             web/evidence.py ARP 매칭(protocol=="ARP")이 소비.
#:
#: (b) 관측·수신기 고유(receiver-specific) → 병합 금지. 병합하면 "그 사본이
#:     실제로 측정/디코드한 값"이라는 의미가 깨진다.
#:   rssi         — radiotap.dbm_antsignal, 이 수신기가 관측한 신호 세기
#:   mcs/mcs_phy  — radiotap MCS 필드, 이 수신기의 PHY 디코드 결과
#:   data_rate    — wlan_radio.data_rate, 이 수신기의 legacy rate 디코드 결과
#:   channel_freq — radiotap.channel.freq, 이 수신기가 튜닝 중이던 채널
#:   tsf          — wlan.fixed.timestamp(비콘 전용). 암호화와 무관하게 항상
#:                  평문이지만(결손이 생기지 않음), estimate_offset이 dedup
#:                  **이전** 단계에서 이미 소비를 끝내므로 그룹 병합 시점엔
#:                  채울 이유가 없다 — 오히려 비-비콘 대표에 다른 비콘의 TSF가
#:                  섞이면 의미가 깨진다.
#:
#: (c) 식별/링크 계층 — 병합 자체가 무의미. 802.11 MAC 헤더 필드는 암호화
#:     여부와 무관하게 항상 평문으로 관측되므로(=결손이 발생하지 않아 채울
#:     필요가 없음), 그 외는 정의상 사본마다 달라야 하는 값이다.
#:   number/epoch/timestamp/retry/subtype/seq — MAC 헤더·프레임 메타(항상 평문)
#:   ta/ra/bssid  — MAC 주소(항상 평문)
#:   length       — frame.len, 물리 프레임 길이(항상 관측됨, 결손 없음)
#:   source       — 캡처 출처 태그 자체(그룹 정체성) — 병합 대상이면 안 됨
_MERGEABLE_DECODED_FIELDS: Tuple[str, ...] = (
    "ip_src", "ip_dst", "icmp_type", "icmp_seq", "icmp_ident",
    "arp_opcode", "tcp_len", "tcp_flags", "eapol_msgnr",
    "current_ap", "reason_code",
)

#: protocol이 이 값 중 하나면 "포괄값"(구체 프로토콜을 식별하지 못한 상태)으로
#: 취급 — _merge_protocol_field가 이 값들을 결손 상태로 보고 채운다.
_GENERIC_PROTOCOL_VALUES = ("", "802.11")


def _merge_protocol_field(rep: Frame, candidate: Frame) -> None:
    """rep.protocol이 포괄값("802.11"/빈 값)이고 candidate가 더 구체적인 값을
    가지면 그 값을 채택한다(rep을 제자리에서 mutate).

    tshark의 `_ws.col.Protocol`은 dissector 체인이 얼마나 깊이 해석했는지의
    함수다 — 같은 프레임이라도 암호화된 사본은 "802.11"(802.11 계층까지만
    해석됨)을, 복호화된 사본은 "EAPOL"/"ICMP"/"ARP" 등 구체 프로토콜을
    보고한다. `_MERGEABLE_DECODED_FIELDS`의 "빈 문자열만 채움" 규칙으로는
    이 필드를 잡을 수 없다 — protocol은 tshark가 항상 뭔가를 채워 넣어
    절대 빈 문자열이 되지 않기 때문이다. rep이 이미 구체값이면(다른 구체값과
    충돌하더라도) 덮어쓰지 않는다 — `_merge_decoded_fields`와 같은 "기존
    값 우선" 원칙(PR #23 리뷰 5라운드).
    """
    if rep.protocol in _GENERIC_PROTOCOL_VALUES and candidate.protocol not in _GENERIC_PROTOCOL_VALUES:
        rep.protocol = candidate.protocol


def _merge_decoded_fields(rep: Frame, candidate: Frame) -> None:
    """rep의 빈 복호화 필드를 candidate의 값으로 채운다(rep을 제자리에서 mutate).

    대표 선정(_prefer_new_representative)은 "어느 사본을 대표로 세울지"만
    정한다 — 대표가 ip_src+icmp_type만 있고 ip_dst/icmp_seq/icmp_ident가
    없는 이른 부분 사본이고, 대표가 아닌 사본이 그 결손 필드를 채운 완전
    사본이면(둘 다 _decoded_score 기준으로는 동률이라 대표 선정만으로는
    가려지지 않는다), 결손 필드가 그대로 비어 남는다. build_ping_matches는
    바로 그 필드들로 흐름을 그룹핑/매칭하므로 RTT/loss가 왜곡될 수 있다
    (PR #23 리뷰 4라운드 Finding B). rep의 필드가 **비어 있고** candidate의
    값이 **비어 있지 않을 때만** 채운다 — rep에 이미 값이 있으면 무조건
    유지한다(대표 선정 우위를 존중, 값 충돌 시 덮어쓰지 않음).

    경고(잠재 지뢰, PR #23 리뷰 4라운드 재리뷰): rep은 **공유 객체를 제자리
    mutate**한다 — rep으로 넘어오는 Frame은 여전히 자신의 원본 소스 리스트
    (`sources[tag]`, 즉 `MergeResult.per_source`)에도 같은 인스턴스로 들어
    있다. 따라서 이 병합이 끝나면 그 소스의 "원본" 프레임이 실제로는 다른
    소스에서 빌려온 필드값을 담고 있게 된다 — per_source를 "소스별 순수
    원본"으로 소비하는 코드가 생기면(현재는 없음) 이 사실을 알아야 한다.
    """
    for field_name in _MERGEABLE_DECODED_FIELDS:
        if not getattr(rep, field_name) and getattr(candidate, field_name):
            setattr(rep, field_name, getattr(candidate, field_name))


class _MatchIndex:
    """키별 슬라이딩 윈도우 dedup 매칭 인덱스.

    all_groups는 최종 출력용 전체 group(창 밖으로 밀려나도 유지 — 절대 삭제 안 함).
    _windows는 키별 "아직 매칭 후보인" group들의 슬라이딩 윈도우(deque)다. 프레임
    전체 순회가 epoch 오름차순이라는 전제 하에 앞쪽(오래된) group부터 버려도
    안전하다. 각 키의 후보 수는 MERGE_MAX_LIVE_GROUPS로 bound한다 — same-source
    밀집 버스트처럼 서로 매치 불가한 프레임이 쌓이면 무한정 늘어나 매 프레임 스캔이
    O(n)이 되는 걸 막는다.

    각 group은 `creation_epoch`(최초 프레임의 epoch, **불변**)와 `epoch`(현재
    대표의 epoch, 대표 교체마다 갱신)를 함께 갖는다 — 퇴거·매칭 거리 판정은
    항상 `creation_epoch` 기준이다. `epoch`(대표 epoch)를 앵커로 쓰면 3+
    소스에서 대표가 여러 번 교체될 때마다 앵커가 밀려 실효 창이 팽창한다:
    w1@0이 group을 만들고 w2@30ms가 매칭·대표 교체(앵커가 30ms로 이동)하면,
    w3@60ms는 w1과는 60ms(창 50ms 밖)이지만 새 앵커(30ms)와는 30ms(창 안)라
    잘못 병합된다 — N소스 체인이면 실효 창이 최대 (N-1)×50ms까지 늘어날 수
    있다(PR #23 리뷰 7라운드 Finding A). creation_epoch를 고정하면 매 매칭이
    항상 "최초 관측 시각"과의 거리로 판정돼 창 정의가 항상 성립한다.
    """

    def __init__(self) -> None:
        self.all_groups: List[Dict[str, Any]] = []
        self._windows: Dict[Tuple, "deque[Dict[str, Any]]"] = {}

    def bucket_len(self, key: Tuple) -> int:
        """키의 현재 매칭 후보 수 — 테스트에서 bound 불변식 검증용."""
        return len(self._windows.get(key, ()))

    def process(self, f: Frame) -> bool:
        """프레임을 기존 group에 병합하거나 새 group을 만든다. 중복이면 True."""
        key = _dedup_key(f)
        dq = self._windows.setdefault(key, deque())
        while dq and f.epoch - dq[0]["creation_epoch"] > MERGE_DEDUP_WINDOW_SEC:
            dq.popleft()  # 창(생성 시점 앵커 기준)을 벗어난 group은 더 이상 매칭 후보가 아니다.

        candidates = [
            g for g in dq
            if f.source not in g["sources"]
            and abs(f.epoch - g["creation_epoch"]) <= MERGE_DEDUP_WINDOW_SEC
        ]
        if candidates:
            # 창 안 후보 중 가장 가까운 것과 매칭(앵커=creation_epoch 기준) —
            # 삽입순 첫 매치가 아니다. 동률(diff 같음)이면 이른 anchor의
            # group을 우선.
            match = min(
                candidates,
                key=lambda g: (abs(f.epoch - g["creation_epoch"]), g["creation_epoch"]),
            )
            match["sources"].add(f.source)
            if _prefer_new_representative(match["rep"], f):
                # 교체 전에 새 대표(f)가 구 대표(match["rep"])의 결손 복호화
                # 필드를 흡수한다 — 교체로 구 대표가 갖고 있던 정보가 사라지는
                # 걸 막는다(PR #23 리뷰 4라운드 Finding B, 5라운드에서 current_ap·
                # reason_code·protocol 포괄값 규칙까지 확장).
                _merge_decoded_fields(f, match["rep"])
                _merge_protocol_field(f, match["rep"])
                match["rep"] = f
                match["epoch"] = f.epoch  # 대표 epoch(출력·정렬용) — creation_epoch(앵커)는 불변.
            else:
                # 대표는 그대로지만, 방금 들어온 후보(f)가 대표의 결손 복호화
                # 필드를 채울 수 있으면 채운다(Finding B, 5라운드 확장).
                _merge_decoded_fields(match["rep"], f)
                _merge_protocol_field(match["rep"], f)
            return True

        group = {"rep": f, "sources": {f.source}, "epoch": f.epoch, "creation_epoch": f.epoch}
        dq.append(group)
        self.all_groups.append(group)
        if len(dq) > MERGE_MAX_LIVE_GROUPS:
            dq.popleft()  # 매칭 후보에서만 제외 — all_groups에는 남아 결과 불변.
        return False


def _format_corrected_timestamp(epoch: float) -> str:
    """보정된 epoch를 로컬 타임존 timestamp 문자열로 재생성.

    tshark 원본 timestamp 포맷(요일·타임존 약어 포함 등)과는 다르지만, 이
    문자열의 유일한 계약은 자기 일관성(캡처 내에서 시각 표기가 실제 epoch와
    맞아야 함)과 `Frame.time_short`가 파싱하는 규칙(공백으로 나눈 파트 중
    콜론 2개+점을 포함하는 것)과의 호환이다 — "%H:%M:%S.%f"는 정확히 15자라
    `time_short`의 `part[:15]` 슬라이스와도 일치한다(테스트로 고정).

    `dt.datetime.fromtimestamp`는 **호스트**(분석을 실행하는 서버)의 로컬
    타임존을 쓴다 — KST 개발 환경/UTC 배포 환경처럼 호스트 tz가 다르면
    표시 시각이 몇 시간 어긋나 보일 수 있다는 우려가 있었다(PR #23 리뷰
    8라운드 Finding A, HIGH로 제기). 검토 결과 **옵션 B(로컬 유지)를
    채택**한다 — 자기 일관성은 어느 호스트에서든 항상 성립하기 때문이다:
    기준(offset 0) 소스의 timestamp 문자열도 tshark의 `frame.time`이
    "같은 분석 호스트"의 로컬 tz로 렌더한 값이므로, 이 함수가 만드는
    비-기준 소스의 timestamp와 항상 **같은 tz 도메인**을 공유한다 — 두
    문자열을 나란히 비교(예: overview 시작/종료, evidence 표)해도 서로
    어긋나지 않는다. "캡처지 tz ≠ 분석 호스트 tz"일 때 전체 타임스탬프가
    (기준·비기준 구분 없이) 일괄 이동해 보이는 것은 pcap 애초의 tshark
    렌더 자체가 갖는 기존 특성(1단계 이전부터, PR #23 이전부터)이지 이
    함수가 새로 만든 문제가 아니다.
    TODO(후속): 분석 호스트 tz가 캡처지 tz와 다른 배포(예: UTC 서버로
    KST 촬영 pcap 분석)에서 사용자에게 표시 tz를 선택하게 하는 옵션화를
    검토할 것 — 이 함수의 로컬 범위를 넘는 전역 표시 정책 변경이라 별도
    스코프로 미룬다.
    """
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S.%f")


def merge_captures(
    sources: "OrderedDict[str, List[Frame]]",
    alignment_sources: Optional["OrderedDict[str, List[Frame]]"] = None,
    reference_tag: Optional[str] = None,
) -> MergeResult:
    """다중 캡처를 시계 정렬 후 dedup·재번호해 단일 타임라인으로 병합한다.

    sources: 태그 → 프레임 리스트(OrderedDict). 나머지 태그는 기준(reference_tag)에
    대해 estimate_offset으로 보정된다. 각 Frame.source는 이미 태깅됨.

    reference_tag: 정렬 기준 태그. 생략하면 sources의 첫 키(기존 동작 — 보통
    "w1"). **reference_tag가 sources에 없어도**(내용 필터로 그 소스가 0건이라
    호출부에서 제외한 경우) alignment_sources에 그 태그가 있으면, 그 비콘
    집합을 기준으로 sources에 남은 **모든** 소스의 오프셋을 추정·적용한다 —
    생존 소스가 1개뿐이어도 이 경로에서는 오프셋 보정이 수행된다(dedup은
    자명하게 0). 기준 소스가 통째로 사라졌다고 오프셋 보정까지 포기하면,
    호출부가 이미 연기해 둔 시간 창(사용자의 실제 벽시계 기준)이 미보정
    (원시 스큐가 남은) epoch에 그대로 적용돼 구간이 어긋나거나 결과가 통째로
    비어버릴 수 있다(PR #23 리뷰 3라운드 Finding A).

    alignment_sources: 주어지면(sources와 동일 태그 체계) 오프셋 추정을 이
    프레임 집합으로 **우선** 수행한다 — pipeline.py가 mac_filter/ip_filter
    없이 비콘만 뽑은 별도 추출 결과(정렬 증거 전용)를 넘긴다. 내용 필터가
    걸린 본 sources는 STA mac_filter(비콘엔 STA 주소 없음)·ip_filter(비콘엔
    IP 없음)로 비콘이 통째로 사라질 수 있어, 그 상태로 오프셋을 추정하면
    TSF 매칭이 실패하고 ±5초 폴백도 183초 스큐엔 무력하다(PR #23 리뷰
    2라운드 Finding A). 정렬 증거로도 tsf 매칭이 부족하면(극히 드묾 — 비콘
    자체가 원래 적은 캡처) 본 sources 프레임 기준으로 2차 시도한다(seq
    폴백 포함 — 정렬 증거는 비콘 전용이라 seq 매칭에 쓸 데이터가 없다).
    None이면(기본) 기존처럼 sources로 직접 추정한다.
    """
    tags = list(sources.keys())
    if reference_tag is None:
        reference_tag = tags[0]
    reference_in_sources = reference_tag in sources
    reference = sources.get(reference_tag, [])
    align_reference = alignment_sources.get(reference_tag) if alignment_sources else None

    # 기준 태그가 sources에 있으면 기존처럼 그 외 나머지만 보정한다. 없으면
    # (내용 필터로 기준 소스가 0건 제외된 경우) sources 쪽엔 비교할 "이미
    # 정확한" 소스가 없다는 뜻이므로, 생존한 소스 **전부**가 정렬 증거
    # (alignment_sources) 기준으로 보정 대상이다(Finding A).
    tags_needing_offset = (
        [t for t in tags if t != reference_tag] if reference_in_sources else list(tags)
    )

    offsets: Dict[str, OffsetResult] = {}
    warnings: List[str] = []
    for tag in tags_needing_offset:
        frames = sources[tag]
        align_frames = alignment_sources.get(tag) if alignment_sources else None
        if align_reference and align_frames:
            result = estimate_offset(align_reference, align_frames)
            if result.method != "tsf":
                # reference가 sources에 없으면(빈 리스트) 이 2차 시도는
                # estimate_offset이 자연히 "none"으로 떨어진다 — 별도 분기 불필요.
                result = estimate_offset(reference, frames)
        else:
            result = estimate_offset(reference, frames)
        offsets[tag] = result
        # epoch를 보정해 통합 타임라인을 만든다. 오프셋이 0이 아닌 소스는
        # timestamp 문자열도 보정 epoch로 재생성한다 — overview 시작/종료·
        # evidence 표가 timestamp 문자열을 그대로 쓰므로, epoch만 보정하고
        # timestamp를 원본(다른 시계 도메인)으로 남겨두면 두 시계가 섞여
        # 표시된다(PR #23 리뷰 2라운드 Finding B). 기준(offset 0) 소스는
        # 항상 원본 timestamp를 유지한다.
        if result.offset_sec:
            for f in frames:
                f.epoch += result.offset_sec
                f.timestamp = _format_corrected_timestamp(f.epoch)
        warnings.extend(result.warnings)
        if result.method == "none":
            warnings.append(f"{tag}: 오프셋 추정 실패 — 원시 시계 그대로 병합됨")

    by_source_raw = {tag: len(sources[tag]) for tag in tags}

    if len(tags) == 1:
        # 생존 소스가 1개뿐 — dedup 대상이 없으니 재번호 없이 그대로
        # 반환한다(기존 파이프라인 하위 호환). only_tag(=tags[0])는
        # reference_tag와 다를 수 있다 — reference_tag가 sources에 없는
        # 경우(위 Finding A 경로)엔 이 유일한 생존 소스도 tags_needing_offset에
        # 포함돼 이미 오프셋이 적용됐을 수 있다. offsets는 그 결과를 그대로
        # 반영한다(reference_tag가 곧 only_tag인 기본 케이스는 tags_needing_offset이
        # 비어 있어 기존처럼 offsets={}가 된다).
        only_tag = tags[0]
        frames = sorted(sources[only_tag], key=lambda f: f.epoch)
        stats: Dict[str, Any] = {
            "window_ms": MERGE_DEDUP_WINDOW_SEC * 1000,
            "duplicates": 0,
            "kept": len(frames),
            "by_source_raw": by_source_raw,
            "coverage": {"both": 0, "only": {only_tag: len(frames)}},
        }
        return MergeResult(
            frames=frames,
            per_source={only_tag: sources[only_tag]},
            offsets=offsets,
            stats=stats,
            warnings=warnings,
        )

    all_frames: List[Frame] = []
    for tag in tags:
        all_frames.extend(sources[tag])
    all_frames.sort(key=lambda f: (f.epoch, f.source, f.number))

    index = _MatchIndex()
    duplicates = sum(1 for f in all_frames if index.process(f))
    all_groups = index.all_groups

    merged = [g["rep"] for g in all_groups]
    merged.sort(key=lambda f: f.epoch)
    for i, f in enumerate(merged):
        # 재번호로 원본 tshark frame.number를 덮어쓰기 **직전** 스탬프 — 이
        # 대표는 자신의 원본 소스 리스트(sources[tag], 즉 per_source)에도
        # 같은 인스턴스로 들어 있으므로, 스탬프 없이 재번호만 하면 그 소스로
        # 역추적할 방법이 사라진다(PR #23 리뷰 6라운드 Finding B — 4라운드에
        # 경고만 남겼던 "번호 지뢰"의 실수정). 이 분기(다중 소스 병합)만
        # 도달하므로 orig_number==0은 항상 "재번호 안 됨"(단일 소스 또는
        # 이 그룹의 비-대표 프레임)과 동치다.
        f.orig_number = f.number
        f.number = i + 1

    both = sum(1 for g in all_groups if len(g["sources"]) >= 2)
    only: Dict[str, int] = {}
    for g in all_groups:
        if len(g["sources"]) == 1:
            (tag,) = g["sources"]
            only[tag] = only.get(tag, 0) + 1

    stats = {
        "window_ms": MERGE_DEDUP_WINDOW_SEC * 1000,
        "duplicates": duplicates,
        "kept": len(merged),
        "by_source_raw": by_source_raw,
        "coverage": {"both": both, "only": only},
    }

    return MergeResult(
        frames=merged,
        per_source={tag: sources[tag] for tag in tags},
        offsets=offsets,
        stats=stats,
        warnings=warnings,
    )
