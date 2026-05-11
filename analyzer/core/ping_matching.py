from typing import Dict, List, Any

from .models import Frame
from .detector import mac_name


PING_MATCH_WINDOW_SEC = 30.0


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


def build_ping_matches(
    frames: List[Frame],
    roles: Dict[str, Dict[str, Any]],
    window_sec: float = PING_MATCH_WINDOW_SEC,
) -> Dict[str, Any]:
    all_requests = []
    requests_queue: Dict[Any, List[Frame]] = {}
    matched_by_req: Dict[int, Frame] = {}

    # 통계용 raw 카운트
    req_total_raw = 0          # ICMP echo request 전체 캡처 수
    req_retry_bit = 0           # 그 중 802.11 retry 비트가 set된 수
    req_retry_skipped = 0       # 동일 seq 재전송으로 dedup된 수
    reply_total_raw = 0         # ICMP echo reply 전체 캡처 수
    reply_retry_bit = 0         # 그 중 retry 비트 set된 수
    reply_unique_keys: set = set()  # (dst,src,seq) unique reply
    seen_req_keys: Dict[Any, float] = {}  # 가장 최근 등장 epoch

    for f in frames:
        if f.is_icmp_request:
            req_total_raw += 1
            if f.retry:
                req_retry_bit += 1
            key = (
                (f.ip_src, f.ip_dst, f.icmp_seq)
                if f.icmp_seq
                else (f.ip_src, f.ip_dst, "")
            )
            # 동일 seq가 윈도우 내 다시 등장하면 재전송으로 간주하고 skip
            last_epoch = seen_req_keys.get(key)
            if last_epoch is not None and (f.epoch - last_epoch) < window_sec:
                req_retry_skipped += 1
                continue
            seen_req_keys[key] = f.epoch
            all_requests.append((key, f))
            requests_queue.setdefault(key, []).append(f)
        elif f.is_icmp_reply:
            reply_total_raw += 1
            if f.retry:
                reply_retry_bit += 1
            key = (
                (f.ip_dst, f.ip_src, f.icmp_seq)
                if f.icmp_seq
                else (f.ip_dst, f.ip_src, "")
            )
            reply_unique_keys.add(key)
            q = requests_queue.get(key)
            if not q:
                continue
            while q and (f.epoch - q[0].epoch) > window_sec:
                q.pop(0)
            if q:
                req = q.pop(0)
                # 이미 매칭된 req에는 첫 reply만 유지 (재전송된 reply 무시)
                if id(req) in matched_by_req:
                    continue
                matched_by_req[id(req)] = f

    full_list = []
    pairs = []
    losses = []

    for key, req in all_requests:
        seq_str = key[2] if len(key) > 2 else ""
        reply_f = matched_by_req.get(id(req))
        if reply_f is not None:
            rtt = (reply_f.epoch - req.epoch) * 1000
            entry = {
                "seq": seq_str,
                "status": "matched",
                "epoch": req.epoch,
                "rtt_ms": round(rtt, 2),
                "req_num": req.number,
                "req_time": req.time_short,
                "reply_num": reply_f.number,
                "reply_time": reply_f.time_short,
                "src": req.ip_src,
                "dst": req.ip_dst,
                "src_mac": mac_name(req.ta, roles) if req.ta else "",
                "dst_mac": mac_name(req.ra, roles) if req.ra else "",
                "has_retry": req.retry or reply_f.retry,
                "req_rssi": req.rssi_first,
            }
            full_list.append(entry)
            pairs.append(entry)
        else:
            entry = {
                "seq": seq_str,
                "status": "loss",
                "epoch": req.epoch,
                "rtt_ms": None,
                "req_num": req.number,
                "req_time": req.time_short,
                "reply_num": None,
                "reply_time": None,
                "src": req.ip_src,
                "dst": req.ip_dst,
                "src_mac": mac_name(req.ta, roles) if req.ta else "",
                "dst_mac": mac_name(req.ra, roles) if req.ra else "",
                "has_retry": req.retry,
                "req_rssi": req.rssi_first,
            }
            full_list.append(entry)
            losses.append(entry)

    full_list.sort(key=lambda x: x["epoch"])
    pairs.sort(key=lambda x: x["epoch"])
    losses.sort(key=lambda x: x["epoch"])

    extra_stats = {
        "req_total_raw": req_total_raw,
        "req_retry_bit": req_retry_bit,           # 802.11 retry 비트 set된 req
        "req_first_send": req_total_raw - req_retry_bit,
        "req_retry_skipped": req_retry_skipped,
        "reply_total_raw": reply_total_raw,
        "reply_retry_bit": reply_retry_bit,        # retry 비트 set된 reply
        "reply_unique_count": len(reply_unique_keys),
    }
    stats = build_ping_stats(pairs, losses, extra=extra_stats)

    return {
        "full_list": full_list,
        "pairs": pairs,
        "losses": losses,
        "stats": stats,
    }
