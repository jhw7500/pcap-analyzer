"""ICMP echo request/reply 매칭 + seq gap 기반 손실 검출.

알고리즘 (3-phase):

1. 흐름 수집: 모든 ICMP echo를 (src, dst, ident) 키의 흐름으로 그룹화.
   같은 (흐름, seq)가 window 내에 다시 나오면 802.11 retry로 dedup.

2. 양방향 매칭: request 흐름 (A,B,id)와 reply 흐름 (B,A,id)이 둘 다 존재하면
   시간순 seq 매칭으로 RTT 계산. 매칭 안 된 request는 "확정 loss"로 분류.

3. seq gap 검출: 단방향 흐름(짝꿍 흐름이 없음)은 흐름 내 seq 단조 증가의 갭만큼을
   "실제 무선구간 손실"로 카운트. 갭이 아닌 정상 송신 사이클은 measurable에는
   포함되지만 RTT는 측정 불가(unmeasurable RTT)로 표시.

loss_pct = (양방향 unmatched + 단방향 seq_gap) / (RTT 측정 가능한 총 시도) × 100
        = loss_count / (count + loss_count) × 100  (역호환)
"""
from typing import Dict, List, Any, Tuple

from .models import Frame
from .detector import mac_name


PING_MATCH_WINDOW_SEC = 30.0
# seq gap 검출 시 wrap-around나 ident 충돌로 인한 거대한 점프는 무시
_MAX_REASONABLE_GAP = 1000


def build_ping_stats(
    pairs: List[Dict[str, Any]],
    losses: List[Dict[str, Any]],
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    rtt_values = [p["rtt_ms"] for p in pairs if p.get("rtt_ms") is not None]
    rtt_sorted = sorted(rtt_values) if rtt_values else []
    total = len(pairs) + len(losses)
    base: Dict[str, Any] = {
        "count": len(rtt_sorted),
        "loss_count": len(losses),
        "loss_pct": round(len(losses) * 100 / total, 1) if total else 0,
    }
    if rtt_sorted:
        base.update({
            "min": round(rtt_sorted[0], 2),
            "max": round(rtt_sorted[-1], 2),
            "avg": round(sum(rtt_sorted) / len(rtt_sorted), 2),
            "p50": round(rtt_sorted[len(rtt_sorted) // 2], 2),
            "p95": round(
                rtt_sorted[min(len(rtt_sorted) - 1, int(len(rtt_sorted) * 0.95))], 2
            ),
            "p99": round(
                rtt_sorted[min(len(rtt_sorted) - 1, int(len(rtt_sorted) * 0.99))], 2
            ),
        })
    else:
        base.update({"min": None, "max": None, "avg": None, "p50": None, "p95": None, "p99": None})
    if extra:
        base.update(extra)
    return base


def _seq_int(s: str) -> int | None:
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _detect_gaps(seqs: List[int]) -> List[int]:
    """정렬된 seq 리스트에서 누락된 seq 번호 리스트를 반환.

    인접 차이가 1보다 크지만 _MAX_REASONABLE_GAP 이하인 경우만 갭으로 인정
    (wrap-around나 ident 충돌로 인한 큰 점프 무시).
    """
    if len(seqs) < 2:
        return []
    missing: List[int] = []
    for prev, cur in zip(seqs, seqs[1:]):
        diff = cur - prev
        if 1 < diff <= _MAX_REASONABLE_GAP:
            missing.extend(range(prev + 1, cur))
    return missing


def _flow_key_for_request(f: Frame) -> Tuple[str, str, str]:
    return (f.ip_src, f.ip_dst, f.icmp_ident)


def _flow_key_for_reply_swapped(f: Frame) -> Tuple[str, str, str]:
    """reply의 (src,dst,ident)를 swap해서 짝꿍 request 흐름 키로 정규화."""
    return (f.ip_dst, f.ip_src, f.icmp_ident)


def _entry_from_frame(
    f: Frame,
    roles: Dict[str, Dict[str, Any]],
    status: str,
    reply: Frame | None = None,
    seq_override: str | None = None,
    epoch_override: float | None = None,
) -> Dict[str, Any]:
    src = f.ip_src or ""
    dst = f.ip_dst or ""
    rtt_ms = None
    reply_num = None
    reply_time = None
    if reply is not None:
        rtt_ms = round((reply.epoch - f.epoch) * 1000, 2)
        reply_num = reply.number
        reply_time = reply.time_short
    return {
        "seq": seq_override if seq_override is not None else f.icmp_seq,
        "status": status,
        "epoch": epoch_override if epoch_override is not None else f.epoch,
        "rtt_ms": rtt_ms,
        "req_num": f.number,
        "req_time": f.time_short,
        "reply_num": reply_num,
        "reply_time": reply_time,
        "src": src,
        "dst": dst,
        "src_mac": mac_name(f.ta, roles) if f.ta else "",
        "dst_mac": mac_name(f.ra, roles) if f.ra else "",
        "has_retry": f.retry or (reply.retry if reply is not None else False),
        "req_rssi": f.rssi_first,
        "ident": f.icmp_ident,
    }


def build_ping_matches(
    frames: List[Frame],
    roles: Dict[str, Dict[str, Any]],
    window_sec: float = PING_MATCH_WINDOW_SEC,
) -> Dict[str, Any]:
    # === Phase 1: 흐름별 수집 + retry dedup ===
    request_flows: Dict[Tuple[str, str, str], List[Frame]] = {}
    reply_flows: Dict[Tuple[str, str, str], List[Frame]] = {}

    req_total_raw = 0
    req_retry_bit = 0
    req_retry_skipped = 0
    reply_total_raw = 0
    reply_retry_bit = 0
    reply_unique_keys: set = set()

    # 같은 (흐름, seq)가 window 내 재등장하면 retry로 dedup
    seen_req: Dict[Tuple[Tuple[str, str, str], str], float] = {}
    seen_reply: Dict[Tuple[Tuple[str, str, str], str], float] = {}

    for f in frames:
        if f.is_icmp_request:
            req_total_raw += 1
            if f.retry:
                req_retry_bit += 1
            flow = _flow_key_for_request(f)
            seq_key = (flow, f.icmp_seq)
            last = seen_req.get(seq_key)
            if last is not None and (f.epoch - last) < window_sec:
                req_retry_skipped += 1
                continue
            seen_req[seq_key] = f.epoch
            request_flows.setdefault(flow, []).append(f)
        elif f.is_icmp_reply:
            reply_total_raw += 1
            if f.retry:
                reply_retry_bit += 1
            flow_swapped = _flow_key_for_reply_swapped(f)
            reply_unique_keys.add((flow_swapped, f.icmp_seq))
            seq_key = (flow_swapped, f.icmp_seq)
            last = seen_reply.get(seq_key)
            if last is not None and (f.epoch - last) < window_sec:
                continue
            seen_reply[seq_key] = f.epoch
            reply_flows.setdefault(flow_swapped, []).append(f)

    # === Phase 2: 양방향 매칭 ===
    full_list: List[Dict[str, Any]] = []
    pairs: List[Dict[str, Any]] = []
    losses: List[Dict[str, Any]] = []

    bidirectional_flows: set = set()
    matched_req_ids: set = set()
    matched_reply_ids: set = set()

    for flow_key, reqs in request_flows.items():
        replies = reply_flows.get(flow_key)
        if not replies:
            continue
        bidirectional_flows.add(flow_key)
        # 시간순으로 같은 seq를 윈도우 내에서 매칭
        reply_by_seq: Dict[str, List[Frame]] = {}
        for r in replies:
            reply_by_seq.setdefault(r.icmp_seq, []).append(r)
        for req in reqs:
            candidates = reply_by_seq.get(req.icmp_seq)
            if not candidates:
                continue
            match = None
            for cand in candidates:
                if id(cand) in matched_reply_ids:
                    continue
                dt = cand.epoch - req.epoch
                if 0 <= dt <= window_sec:
                    match = cand
                    break
            if match is not None:
                matched_req_ids.add(id(req))
                matched_reply_ids.add(id(match))
                entry = _entry_from_frame(req, roles, "matched", reply=match)
                full_list.append(entry)
                pairs.append(entry)

    # === Phase 3: 흐름별 seq 교차 검증 ===
    # 양방향 흐름은 req/reply seq 집합의 교집합·차집합으로 분류:
    #   verified_cycle   = req_seqs ∩ reply_seqs   → 양쪽 다 관측, 무선 손실 0
    #   reply_missing    = req_seqs − reply_seqs   → req만 관측, **확정 무선 손실 후보**
    #   request_missing  = reply_seqs − req_seqs   → reply만 관측, **캡처 누락** (무선 OK)
    #   fully_unobserved = seq range gap           → 양쪽 모두 미관측 (구분 불가)
    # 단방향 흐름은 seq gap만 loss로 잡고 나머지는 unmeasurable.

    seq_gap_losses = 0
    unmeasurable_count = 0
    verified_cycle_count = 0
    reply_missing_count = 0
    request_missing_count = 0
    fully_unobserved_count = 0
    flow_diag: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []

    for flow_key, reqs in request_flows.items():
        is_bidirectional = flow_key in bidirectional_flows
        req_seq_set = {r.icmp_seq for r in reqs if r.icmp_seq}
        req_seqs_int = sorted({_seq_int(s) for s in req_seq_set} - {None})

        if is_bidirectional:
            replies = reply_flows[flow_key]
            reply_seq_set = {r.icmp_seq for r in replies if r.icmp_seq}

            verified_set = req_seq_set & reply_seq_set
            reply_missing_set = req_seq_set - reply_seq_set
            request_missing_set = reply_seq_set - req_seq_set

            verified_cycle_count += len(verified_set)
            reply_missing_count += len(reply_missing_set)
            request_missing_count += len(request_missing_set)

            # 확정 무선 손실 후보: req는 보였는데 같은 seq의 reply가 캡처 어디에도 없음
            for req in reqs:
                if req.icmp_seq in reply_missing_set and id(req) not in matched_req_ids:
                    entry = _entry_from_frame(req, roles, "loss")
                    full_list.append(entry)
                    losses.append(entry)

            # 캡처 누락 (request_missing): reply만 보이는 케이스
            for rep in replies:
                if rep.icmp_seq in request_missing_set:
                    observations.append(_observation_entry(rep, roles, "reply"))

            # 양쪽 모두 미관측 seq 갭 (capture 또는 wireless 둘 다 가능, 구분 불가)
            union_seqs_int = sorted(({_seq_int(s) for s in (req_seq_set | reply_seq_set)} - {None}))
            missing_seqs = _detect_gaps(union_seqs_int)
            for ms in missing_seqs:
                _record_phantom_loss(losses, full_list, reqs, ms, "unknown")
            fully_unobserved_count += len(missing_seqs)
            seq_gap_losses += len(missing_seqs)

            flow_diag.append({
                "flow": list(flow_key),
                "direction": "bidirectional",
                "verified_cycle": len(verified_set),
                "reply_missing": len(reply_missing_set),
                "request_missing": len(request_missing_set),
                "fully_unobserved": len(missing_seqs),
                "seq_min": union_seqs_int[0] if union_seqs_int else None,
                "seq_max": union_seqs_int[-1] if union_seqs_int else None,
                "matched_rtt": len([r for r in reqs if id(r) in matched_req_ids]),
            })
        else:
            # request-only 단방향: seq gap만 loss, 나머지는 unmeasurable
            unmatched = [r for r in reqs if id(r) not in matched_req_ids]
            missing_seqs = _detect_gaps(req_seqs_int)
            for ms in missing_seqs:
                _record_phantom_loss(losses, full_list, reqs, ms, "request")
            seq_gap_losses += len(missing_seqs)
            unmeasurable_count += len(unmatched)
            for req in unmatched:
                observations.append(_observation_entry(req, roles, "request"))

            flow_diag.append({
                "flow": list(flow_key),
                "direction": "request-only",
                "unique_seqs": len(req_seqs_int),
                "seq_min": req_seqs_int[0] if req_seqs_int else None,
                "seq_max": req_seqs_int[-1] if req_seqs_int else None,
                "seq_gap_losses": len(missing_seqs),
            })

    # reply-only 단방향: request 흐름이 없는 reply 흐름
    for flow_key, replies in reply_flows.items():
        if flow_key in request_flows:
            continue
        reply_seqs_int = sorted({n for r in replies for n in [_seq_int(r.icmp_seq)] if n is not None})
        missing_seqs = _detect_gaps(reply_seqs_int)
        for ms in missing_seqs:
            _record_phantom_loss(losses, full_list, replies, ms, "reply")
        seq_gap_losses += len(missing_seqs)
        unmeasurable_count += len(replies)
        for rep in replies:
            observations.append(_observation_entry(rep, roles, "reply"))
        flow_diag.append({
            "flow": list(flow_key),
            "direction": "reply-only",
            "unique_seqs": len(reply_seqs_int),
            "seq_min": reply_seqs_int[0] if reply_seqs_int else None,
            "seq_max": reply_seqs_int[-1] if reply_seqs_int else None,
            "seq_gap_losses": len(missing_seqs),
        })

    full_list.sort(key=lambda x: x["epoch"])
    pairs.sort(key=lambda x: x["epoch"])
    losses.sort(key=lambda x: x["epoch"])
    observations.sort(key=lambda x: x["epoch"])

    # 캡처 모드 판정
    if bidirectional_flows and len(bidirectional_flows) == len(request_flows):
        capture_mode = "bidirectional"
    elif bidirectional_flows:
        capture_mode = "mixed"
    elif request_flows or reply_flows:
        capture_mode = "unidirectional"
    else:
        capture_mode = "none"

    extra_stats = {
        "req_total_raw": req_total_raw,
        "req_retry_bit": req_retry_bit,
        "req_first_send": req_total_raw - req_retry_bit,
        "req_retry_skipped": req_retry_skipped,
        "reply_total_raw": reply_total_raw,
        "reply_retry_bit": reply_retry_bit,
        "reply_unique_count": len(reply_unique_keys),
        # 신규 필드
        "rtt_matched": len(pairs),
        "seq_gap_losses": seq_gap_losses,
        "unmeasurable_count": unmeasurable_count,
        # Phase 2b 교차 검증 결과 — 양방향 흐름에서만 의미 있음
        "verified_cycle": verified_cycle_count,
        "reply_missing": reply_missing_count,      # req만 보임 = 확정 무선 손실 후보
        "request_missing": request_missing_count,  # reply만 보임 = 캡처 누락
        "fully_unobserved": fully_unobserved_count,  # 양쪽 모두 미관측 = 구분 불가
        "capture_mode": capture_mode,
        "flows": flow_diag,
    }
    stats = build_ping_stats(pairs, losses, extra=extra_stats)
    # loss_pct 재정의:
    # 분모는 "측정 가능한 총 송신 사이클" = matched + losses + unmeasurable
    # unmeasurable = 단방향 캡처에서 송신은 캡처됐으나 RTT 측정 불가한 케이스
    measurable_base = len(pairs) + len(losses) + unmeasurable_count
    if measurable_base:
        stats["loss_pct"] = round(len(losses) * 100 / measurable_base, 2)
    else:
        stats["loss_pct"] = 0

    return {
        "full_list": full_list,
        "pairs": pairs,
        "losses": losses,
        "observations": observations,
        "stats": stats,
    }


def _observation_entry(
    f: Frame,
    roles: Dict[str, Dict[str, Any]],
    direction: str,
) -> Dict[str, Any]:
    """관찰됐지만 RTT 측정 불가한 ICMP 프레임 entry.

    direction: "request" (echo request만 캡처) | "reply" (echo reply만 캡처)
    """
    return {
        "status": "observed",
        "direction": direction,
        "icmp_type": f.icmp_type,  # "8"=request, "0"=reply
        "seq": f.icmp_seq,
        "ident": f.icmp_ident,
        "frame_num": f.number,
        "time": f.time_short,
        "epoch": f.epoch,
        "src": f.ip_src or "",
        "dst": f.ip_dst or "",
        "src_mac": mac_name(f.ta, roles) if f.ta else "",
        "dst_mac": mac_name(f.ra, roles) if f.ra else "",
        "has_retry": f.retry,
        "rssi": f.rssi_first,
    }


def _record_phantom_loss(
    losses: List[Dict[str, Any]],
    full_list: List[Dict[str, Any]],
    nearby_frames: List[Frame],
    missing_seq: int,
    direction: str,
) -> None:
    """seq gap으로 추정된 손실을 가상 entry로 기록.

    실제 frame이 없으므로 직전 frame의 메타데이터를 빌려서 추정 epoch을 채운다.
    """
    if not nearby_frames:
        return
    # 직전 seq의 frame을 찾는다 (시간 추정용)
    anchor = nearby_frames[0]
    best_diff = None
    for f in nearby_frames:
        seq_n = _seq_int(f.icmp_seq)
        if seq_n is None or seq_n >= missing_seq:
            continue
        diff = missing_seq - seq_n
        if best_diff is None or diff < best_diff:
            best_diff = diff
            anchor = f
    entry = {
        "seq": str(missing_seq),
        "status": "loss_gap",
        "epoch": anchor.epoch,
        "rtt_ms": None,
        "req_num": None,
        # 추정 손실은 실제 손실 프레임이 없으므로, 시간 근거가 된 anchor 프레임
        # 번호를 남겨 증거 소싱(ping_loss_evidence)이 frame_ref로 쓸 수 있게 한다.
        "anchor_num": anchor.number,
        "req_time": anchor.time_short,
        "reply_num": None,
        "reply_time": None,
        "src": anchor.ip_src if direction == "request" else anchor.ip_dst,
        "dst": anchor.ip_dst if direction == "request" else anchor.ip_src,
        "src_mac": "",
        "dst_mac": "",
        "has_retry": False,
        "req_rssi": None,
        "ident": anchor.icmp_ident,
        "gap_direction": direction,  # "request" | "reply"
    }
    full_list.append(entry)
    losses.append(entry)
