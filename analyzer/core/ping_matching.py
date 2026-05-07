from typing import Dict, List, Any

from .models import Frame
from .detector import mac_name


PING_MATCH_WINDOW_SEC = 30.0


def build_ping_stats(
    pairs: List[Dict[str, Any]], losses: List[Dict[str, Any]]
) -> Dict[str, Any]:
    rtt_values = [p["rtt_ms"] for p in pairs if p.get("rtt_ms") is not None]
    rtt_sorted = sorted(rtt_values) if rtt_values else []
    total = len(pairs) + len(losses)
    if not rtt_sorted:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "avg": None,
            "p50": None,
            "p95": None,
            "p99": None,
            "loss_count": len(losses),
            "loss_pct": round(len(losses) * 100 / total, 1) if total else 0,
        }
    return {
        "count": len(rtt_sorted),
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
        "loss_count": len(losses),
        "loss_pct": round(len(losses) * 100 / total, 1) if total else 0,
    }


def build_ping_matches(
    frames: List[Frame],
    roles: Dict[str, Dict[str, Any]],
    window_sec: float = PING_MATCH_WINDOW_SEC,
) -> Dict[str, Any]:
    all_requests = []
    requests_queue: Dict[Any, List[Frame]] = {}
    matched_by_req: Dict[int, Frame] = {}

    for f in frames:
        if f.is_icmp_request and not f.retry:
            key = (
                (f.ip_src, f.ip_dst, f.icmp_seq)
                if f.icmp_seq
                else (f.ip_src, f.ip_dst, "")
            )
            all_requests.append((key, f))
            requests_queue.setdefault(key, []).append(f)
        elif f.is_icmp_reply:
            key = (
                (f.ip_dst, f.ip_src, f.icmp_seq)
                if f.icmp_seq
                else (f.ip_dst, f.ip_src, "")
            )
            q = requests_queue.get(key)
            if not q:
                continue
            while q and (f.epoch - q[0].epoch) > window_sec:
                q.pop(0)
            if q:
                req = q.pop(0)
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

    stats = build_ping_stats(pairs, losses)

    return {
        "full_list": full_list,
        "pairs": pairs,
        "losses": losses,
        "stats": stats,
    }
