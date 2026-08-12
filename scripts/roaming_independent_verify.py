#!/usr/bin/env python3
"""분석기와 독립적으로 PCAP/STA 로그 로밍 원장을 만들고 결과를 대조한다.

이 스크립트는 의도적으로 ``analyzer`` 패키지를 import하지 않는다. 원시 PCAP은
``tshark`` 필드만 읽고, STA 체감시간은 wpa_supplicant 로그 원문에서 직접 만든다.
분석기 결과 JSON은 마지막 비교 단계에서만 읽는다. 따라서 분석기와 같은 버그를
공유하는 자기검증이 아니라 별도 구현 간 교차검증으로 사용할 수 있다.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import itertools
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
from typing import Any, Iterable, Optional


EVENT_FILTER = (
    "(wlan.fc.type_subtype == 0x0000 || "
    "wlan.fc.type_subtype == 0x0002 || "
    "wlan.fc.type_subtype == 0x000b || eapol)"
)
EVENT_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "wlan.fc.retry",
    "wlan.fc.type_subtype",
    "wlan.ta",
    "wlan.ra",
    "wlan.bssid",
    "wlan.seq",
    "wlan.fixed.current_ap",
    "wlan_rsna_eapol.keydes.msgnr",
)
BEACON_FIELDS = ("frame.time_epoch", "wlan.bssid", "wlan.fixed.timestamp")

DEFAULT_DEDUP_MS = 50.0
DEFAULT_ASSOC_ATTEMPT_MS = 1000.0
DEFAULT_AUTH_MAX_MS = 10_000.0
DEFAULT_STA_MATCH_MS = 250.0
DEFAULT_COMPARE_MS = 50.0
DEFAULT_STA_SLOW_MS = 150.0
DEFAULT_PCAP_SLOW_MS = 100.0
DEFAULT_STATION_UTC_OFFSET = "+09:00"

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")
_ROAM_RE = re.compile(r"Control interface command 'ROAM ([0-9a-f:]{17})'", re.I)
_CONNECTED_RE = re.compile(
    r"CTRL-EVENT-CONNECTED - Connection to ([0-9a-f:]{17})", re.I
)
_FAIL_RE = re.compile(
    r"(AUTH_TIMED_OUT|CTRL-EVENT-ASSOC-REJECT|CTRL-EVENT-DISCONNECTED)"
)


@dataclass
class PacketEvent:
    source: str
    number: int
    epoch: float
    retry: bool
    subtype: int
    ta: str
    ra: str
    bssid: str
    seq: str
    current_ap: str
    eapol_msg: str


@dataclass
class RoamTransaction:
    sta: str
    ap: str
    auth_epoch: Optional[float]
    assoc_epoch: float
    auth_number: Optional[int]
    assoc_number: int
    auth_basis: Optional[str]
    gap_ms: Optional[float]
    pcap_total_ms: Optional[float]
    sta_source: Optional[str] = None
    sta_total_ms: Optional[float] = None
    is_slow: bool = False
    slow_basis: Optional[str] = None


@dataclass
class StationRoam:
    station: str
    index: int
    target_ap: str
    command_epoch: float
    connected_epoch: Optional[float]
    total_ms: Optional[float]
    failed: bool
    fail_reason: str


@dataclass
class PairScore:
    station: str
    sta: str
    offset_sec: float
    matched: int
    residual_mad_ms: Optional[float]


def _first(value: str) -> str:
    return (value or "").split(",", 1)[0].strip()


def _bool(value: str) -> bool:
    return _first(value).lower() in {"1", "true", "yes"}


def _subtype(value: str) -> int:
    raw = _first(value)
    return int(raw, 16) if raw.lower().startswith("0x") else int(raw)


def _percentile(values: list[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * fraction
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def _tshark_rows(
    paths: Iterable[Path], fields: tuple[str, ...], display_filter: str, tshark: str
) -> Iterable[tuple[Path, list[str]]]:
    for path in paths:
        cmd = [tshark, "-r", str(path), "-T", "fields"]
        for field in fields:
            cmd.extend(["-e", field])
        cmd.extend(["-E", "occurrence=f", "-Y", display_filter])
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            cols = line.rstrip("\r\n").split("\t")
            cols.extend([""] * (len(fields) - len(cols)))
            yield path, cols
        assert proc.stderr is not None
        stderr = proc.stderr.read()
        rc = proc.wait()
        if rc != 0:
            raise RuntimeError(f"tshark 실패({path}, exit={rc}): {stderr[-1000:]}")


def extract_packet_events(
    sources: "OrderedDict[str, list[Path]]", tshark: str = "tshark"
) -> tuple["OrderedDict[str, list[PacketEvent]]", dict[str, int]]:
    out: "OrderedDict[str, list[PacketEvent]]" = OrderedDict()
    counts: dict[str, int] = {}
    for tag, paths in sources.items():
        events: list[PacketEvent] = []
        for _, cols in _tshark_rows(paths, EVENT_FIELDS, EVENT_FILTER, tshark):
            try:
                events.append(
                    PacketEvent(
                        source=tag,
                        number=int(_first(cols[0])),
                        epoch=float(_first(cols[1])),
                        retry=_bool(cols[2]),
                        subtype=_subtype(cols[3]),
                        ta=_first(cols[4]).lower(),
                        ra=_first(cols[5]).lower(),
                        bssid=_first(cols[6]).lower(),
                        seq=_first(cols[7]),
                        current_ap=_first(cols[8]).lower(),
                        eapol_msg=_first(cols[9]),
                    )
                )
            except (ValueError, IndexError):
                continue
        events.sort(key=lambda event: (event.epoch, event.number))
        out[tag] = events
        counts[tag] = len(events)
    return out, counts


def extract_beacons(
    sources: "OrderedDict[str, list[Path]]", tshark: str = "tshark"
) -> "OrderedDict[str, dict[tuple[str, str], float]]":
    out: "OrderedDict[str, dict[tuple[str, str], float]]" = OrderedDict()
    for tag, paths in sources.items():
        beacons: dict[tuple[str, str], float] = {}
        for _, cols in _tshark_rows(
            paths, BEACON_FIELDS, "wlan.fc.type_subtype == 0x0008", tshark
        ):
            try:
                epoch = float(_first(cols[0]))
            except (ValueError, IndexError):
                continue
            bssid, tsf = _first(cols[1]).lower(), _first(cols[2])
            if bssid and tsf:
                beacons.setdefault((bssid, tsf), epoch)
        out[tag] = beacons
    return out


def estimate_tsf_offsets(
    beacons: "OrderedDict[str, dict[tuple[str, str], float]]", reference: str
) -> dict[str, dict[str, Any]]:
    if reference not in beacons:
        raise ValueError(f"기준 소스가 없다: {reference}")
    ref = beacons[reference]
    result: dict[str, dict[str, Any]] = {
        reference: {"offset_sec": 0.0, "method": "reference", "pairs": len(ref)}
    }
    for tag, current in beacons.items():
        if tag == reference:
            continue
        diffs = [ref[key] - epoch for key, epoch in current.items() if key in ref]
        if not diffs:
            raise RuntimeError(f"{tag}: 공통 (BSSID, TSF) 비콘이 없어 독립 정렬 불가")
        median = statistics.median(diffs)
        q1 = _percentile(diffs, 0.25)
        q3 = _percentile(diffs, 0.75)
        result[tag] = {
            "offset_sec": median,
            "method": "tsf",
            "pairs": len(diffs),
            "iqr_ms": round(((q3 or median) - (q1 or median)) * 1000, 3),
        }
    return result


def _dedup_key(event: PacketEvent) -> tuple[Any, ...]:
    if event.seq:
        return ("s", event.ta, event.seq, event.subtype, event.retry)
    return ("c", event.subtype, event.ta or event.ra, event.retry)


def align_and_dedup(
    per_source: "OrderedDict[str, list[PacketEvent]]",
    offsets: dict[str, dict[str, Any]],
    dedup_ms: float = DEFAULT_DEDUP_MS,
) -> tuple[list[PacketEvent], int]:
    merged: list[PacketEvent] = []
    for tag, events in per_source.items():
        offset = float(offsets[tag]["offset_sec"])
        for event in events:
            event.epoch += offset
            merged.append(event)
    merged.sort(key=lambda event: (event.epoch, event.source, event.number))

    window_sec = dedup_ms / 1000.0
    live: dict[tuple[Any, ...], deque[dict[str, Any]]] = defaultdict(deque)
    groups: list[dict[str, Any]] = []
    duplicates = 0
    for event in merged:
        key = _dedup_key(event)
        candidates = live[key]
        while candidates and event.epoch - candidates[0]["epoch"] > window_sec:
            candidates.popleft()
        match = next(
            (
                group
                for group in candidates
                if event.source not in group["sources"]
                and abs(event.epoch - group["epoch"]) <= window_sec
            ),
            None,
        )
        if match is None:
            group = {"event": event, "epoch": event.epoch, "sources": {event.source}}
            candidates.append(group)
            groups.append(group)
            continue
        duplicates += 1
        match["sources"].add(event.source)
        representative: PacketEvent = match["event"]
        if not representative.current_ap and event.current_ap:
            representative.current_ap = event.current_ap
        if not representative.eapol_msg and event.eapol_msg:
            representative.eapol_msg = event.eapol_msg

    events = [group["event"] for group in groups]
    events.sort(key=lambda event: (event.epoch, event.source, event.number))
    return events, duplicates


def detect_station_macs(events: list[PacketEvent]) -> list[str]:
    counts = Counter(
        event.ta for event in events if event.subtype in {0, 2} and event.ta
    )
    if not counts:
        return []
    # 반복 로밍 시험에서는 STA가 수백 회 나타난다. 작은 일반 캡처도 지원하기 위해
    # 최대치의 10% 이상이면서 최소 2회인 송신자를 STA 후보로 둔다.
    threshold = max(2, int(max(counts.values()) * 0.1))
    return sorted(mac for mac, count in counts.items() if count >= threshold)


def build_packet_ledger(
    events: list[PacketEvent],
    sta_macs: Iterable[str],
    assoc_attempt_ms: float = DEFAULT_ASSOC_ATTEMPT_MS,
    auth_max_ms: float = DEFAULT_AUTH_MAX_MS,
) -> tuple[list[RoamTransaction], dict[str, int]]:
    stas = set(sta_macs)
    anchors: dict[str, tuple[PacketEvent, str]] = {}
    last_assoc: dict[str, PacketEvent] = {}
    transactions: list[RoamTransaction] = []
    collapsed = 0
    auth_max_sec = auth_max_ms / 1000.0
    attempt_sec = assoc_attempt_ms / 1000.0

    for event in events:
        if event.subtype == 11:
            if event.ta in stas:
                anchors[event.ta] = (event, "auth_request")
            elif event.ra in stas:
                previous = anchors.get(event.ra)
                if previous is None or event.epoch - previous[0].epoch > 1.0:
                    anchors[event.ra] = (event, "auth_response")
            continue
        if event.subtype not in {0, 2} or event.ta not in stas:
            continue

        anchor = anchors.pop(event.ta, None)
        if anchor is not None:
            delta = event.epoch - anchor[0].epoch
            if delta < 0 or delta > auth_max_sec:
                anchor = None
        if anchor is None:
            previous = last_assoc.get(event.ta)
            if (
                previous is not None
                and 0 <= event.epoch - previous.epoch <= attempt_sec
                and previous.subtype == event.subtype
                and previous.ra == event.ra
            ):
                collapsed += 1
                continue

        auth = anchor[0] if anchor else None
        basis = anchor[1] if anchor else None
        transactions.append(
            RoamTransaction(
                sta=event.ta,
                ap=event.ra,
                auth_epoch=auth.epoch if auth else None,
                assoc_epoch=event.epoch,
                auth_number=auth.number if auth else None,
                assoc_number=event.number,
                auth_basis=basis,
                gap_ms=round((event.epoch - auth.epoch) * 1000, 1) if auth else None,
                pcap_total_ms=None,
            )
        )
        last_assoc[event.ta] = event

    msg4: dict[tuple[str, str], list[float]] = defaultdict(list)
    for event in events:
        if event.eapol_msg == "4" and event.ta in stas:
            msg4[(event.ta, event.ra)].append(event.epoch)
    for epochs in msg4.values():
        epochs.sort()
    for transaction in transactions:
        if transaction.auth_epoch is None:
            continue
        candidates = msg4.get((transaction.sta, transaction.ap), [])
        pos = bisect_left(candidates, transaction.assoc_epoch)
        if pos < len(candidates) and candidates[pos] - transaction.assoc_epoch <= 5.0:
            transaction.pcap_total_ms = round(
                (candidates[pos] - transaction.auth_epoch) * 1000, 1
            )
    return transactions, {"association_repeats_collapsed": collapsed}


def _parse_utc_offset(value: str) -> timezone:
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", value)
    if not match:
        raise ValueError(f"UTC offset 형식은 +09:00과 같아야 한다: {value}")
    hours, minutes = int(match.group(2)), int(match.group(3))
    if hours > 23 or minutes > 59:
        raise ValueError(f"유효하지 않은 UTC offset: {value}")
    delta = timedelta(hours=hours, minutes=minutes)
    if match.group(1) == "-":
        delta = -delta
    return timezone(delta)


def _parse_local_epoch(value: str, tz: timezone) -> float:
    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
    return parsed.replace(tzinfo=tz).timestamp()


def parse_wpa_log(
    path: Path, station: str, tz: Optional[timezone] = None
) -> list[StationRoam]:
    roams: list[StationRoam] = []
    pending: Optional[dict[str, Any]] = None
    log_timezone = tz or _parse_utc_offset(DEFAULT_STATION_UTC_OFFSET)

    def close_failed(reason: str) -> None:
        nonlocal pending
        if pending is None:
            return
        roams.append(
            StationRoam(
                station=station,
                index=len(roams) + 1,
                target_ap=pending["target"],
                command_epoch=pending["epoch"],
                connected_epoch=None,
                total_ms=None,
                failed=True,
                fail_reason=reason,
            )
        )
        pending = None

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ts_match = _TS_RE.match(line)
        if not ts_match:
            continue
        epoch = _parse_local_epoch(ts_match.group(1), log_timezone)
        roam_match = _ROAM_RE.search(line)
        if roam_match:
            close_failed("next_roam_before_connected")
            pending = {"epoch": epoch, "target": roam_match.group(1).lower()}
            continue
        connected_match = _CONNECTED_RE.search(line)
        if connected_match and pending is not None:
            target = connected_match.group(1).lower()
            total_ms = round((epoch - pending["epoch"]) * 1000, 1)
            roams.append(
                StationRoam(
                    station=station,
                    index=len(roams) + 1,
                    target_ap=target,
                    command_epoch=pending["epoch"],
                    connected_epoch=epoch,
                    total_ms=total_ms,
                    failed=False,
                    fail_reason="",
                )
            )
            pending = None
            continue
        fail_match = _FAIL_RE.search(line)
        if fail_match and pending is not None:
            close_failed(fail_match.group(1))
    close_failed("end_of_log")
    return roams


def _nearest_delta(epochs: list[float], expected: float) -> Optional[float]:
    if not epochs:
        return None
    pos = bisect_left(epochs, expected)
    candidates = epochs[max(0, pos - 1) : min(len(epochs), pos + 2)]
    return min((epoch - expected for epoch in candidates), key=abs, default=None)


def score_station_binding(
    station: str,
    station_roams: list[StationRoam],
    sta: str,
    packet_roams: list[RoamTransaction],
    tolerance_ms: float = DEFAULT_STA_MATCH_MS,
) -> PairScore:
    successes = [roam for roam in station_roams if not roam.failed]
    packet_by_ap: dict[str, list[float]] = defaultdict(list)
    for roam in packet_roams:
        if roam.sta == sta and roam.auth_epoch is not None:
            packet_by_ap[roam.ap].append(roam.auth_epoch)
    for epochs in packet_by_ap.values():
        epochs.sort()

    candidate_offsets: Counter[float] = Counter()
    for roam in successes:
        epochs = packet_by_ap.get(roam.target_ap, [])
        lo = bisect_left(epochs, roam.command_epoch - 15.0)
        hi = bisect_right(epochs, roam.command_epoch + 15.0)
        for epoch in epochs[lo:hi]:
            candidate_offsets[round(epoch - roam.command_epoch, 3)] += 1
    if not candidate_offsets:
        return PairScore(station, sta, 0.0, 0, None)

    tolerance = tolerance_ms / 1000.0
    best_offset, best_count, best_residuals = 0.0, -1, []
    for offset, _ in candidate_offsets.most_common(80):
        residuals = []
        for roam in successes:
            delta = _nearest_delta(
                packet_by_ap.get(roam.target_ap, []), roam.command_epoch + offset
            )
            if delta is not None and abs(delta) <= tolerance:
                residuals.append(delta)
        if len(residuals) > best_count:
            best_offset, best_count, best_residuals = offset, len(residuals), residuals
    if best_residuals:
        best_offset += statistics.median(best_residuals)
    residuals = []
    for roam in successes:
        delta = _nearest_delta(
            packet_by_ap.get(roam.target_ap, []), roam.command_epoch + best_offset
        )
        if delta is not None and abs(delta) <= tolerance:
            residuals.append(delta)
    mad = (
        statistics.median(
            abs(value - statistics.median(residuals)) for value in residuals
        )
        * 1000
        if residuals
        else None
    )
    return PairScore(
        station=station,
        sta=sta,
        offset_sec=best_offset,
        matched=len(residuals),
        residual_mad_ms=round(mad, 3) if mad is not None else None,
    )


def bind_stations(
    station_ledgers: dict[str, list[StationRoam]],
    packet_roams: list[RoamTransaction],
    explicit: Optional[dict[str, str]] = None,
    tolerance_ms: float = DEFAULT_STA_MATCH_MS,
) -> tuple[dict[str, PairScore], dict[str, dict[str, PairScore]]]:
    stations = list(station_ledgers)
    stas = sorted({roam.sta for roam in packet_roams})
    matrix = {
        station: {
            sta: score_station_binding(
                station, station_ledgers[station], sta, packet_roams, tolerance_ms
            )
            for sta in stas
        }
        for station in stations
    }
    if explicit:
        unknown_stations = sorted(set(explicit) - set(stations))
        missing_stations = sorted(set(stations) - set(explicit))
        unknown_macs = sorted(set(explicit.values()) - set(stas))
        if unknown_stations or missing_stations or unknown_macs:
            raise ValueError(
                "명시적 STA 바인딩 불완전: "
                f"unknown_station={unknown_stations}, missing_station={missing_stations}, "
                f"unknown_mac={unknown_macs}"
            )
        return {
            station: matrix[station][explicit[station]] for station in stations
        }, matrix
    if len(stations) > len(stas):
        raise RuntimeError("STA 로그 수가 패킷 STA 후보 수보다 많아 자동 바인딩 불가")
    best: Optional[tuple[tuple[int, float], dict[str, PairScore]]] = None
    for selected in itertools.permutations(stas, len(stations)):
        binding = {
            station: matrix[station][sta] for station, sta in zip(stations, selected)
        }
        matched = sum(score.matched for score in binding.values())
        mad = sum(
            score.residual_mad_ms if score.residual_mad_ms is not None else 1_000_000
            for score in binding.values()
        )
        rank = (matched, -mad)
        if best is None or rank > best[0]:
            best = (rank, binding)
    if best is None:
        raise RuntimeError("STA 자동 바인딩 후보가 없다")
    return best[1], matrix


def correlate_station_logs(
    station_ledgers: dict[str, list[StationRoam]],
    packet_roams: list[RoamTransaction],
    bindings: dict[str, PairScore],
    tolerance_ms: float = DEFAULT_STA_MATCH_MS,
) -> dict[str, Any]:
    tolerance = tolerance_ms / 1000.0
    used_packets: set[int] = set()
    unmatched_logs: list[dict[str, Any]] = []
    matched = 0
    for station, score in bindings.items():
        candidates_by_ap: dict[str, list[tuple[float, int]]] = defaultdict(list)
        for index, packet in enumerate(packet_roams):
            if packet.sta == score.sta and packet.auth_epoch is not None:
                candidates_by_ap[packet.ap].append((packet.auth_epoch, index))
        for values in candidates_by_ap.values():
            values.sort()
        for log_roam in station_ledgers[station]:
            if log_roam.failed:
                continue
            expected = log_roam.command_epoch + score.offset_sec
            candidates = candidates_by_ap.get(log_roam.target_ap, [])
            epochs = [value[0] for value in candidates]
            pos = bisect_left(epochs, expected)
            nearby = candidates[max(0, pos - 2) : min(len(candidates), pos + 3)]
            available = [item for item in nearby if item[1] not in used_packets]
            if not available:
                unmatched_logs.append(asdict(log_roam))
                continue
            epoch, packet_index = min(
                available, key=lambda item: abs(item[0] - expected)
            )
            if abs(epoch - expected) > tolerance:
                unmatched_logs.append(asdict(log_roam))
                continue
            packet = packet_roams[packet_index]
            packet.sta_source = station
            packet.sta_total_ms = log_roam.total_ms
            used_packets.add(packet_index)
            matched += 1
    unmatched_packets = [
        asdict(packet)
        for index, packet in enumerate(packet_roams)
        if index not in used_packets
    ]
    return {
        "matched": matched,
        "unmatched_station_success": unmatched_logs,
        "unmatched_packets": unmatched_packets,
    }


def classify_transactions(
    transactions: list[RoamTransaction],
    sta_slow_ms: float = DEFAULT_STA_SLOW_MS,
    pcap_slow_ms: float = DEFAULT_PCAP_SLOW_MS,
) -> None:
    for transaction in transactions:
        if transaction.sta_total_ms is not None:
            transaction.is_slow = transaction.sta_total_ms > sta_slow_ms
            transaction.slow_basis = "sta_log_total"
        elif transaction.pcap_total_ms is not None:
            transaction.is_slow = transaction.pcap_total_ms > pcap_slow_ms
            transaction.slow_basis = "total"
        elif transaction.gap_ms is not None and transaction.gap_ms > pcap_slow_ms:
            transaction.is_slow = True
            transaction.slow_basis = "gap_lower_bound"
        else:
            transaction.is_slow = False
            transaction.slow_basis = None


def _event_epoch(value: dict[str, Any]) -> Optional[float]:
    for key in ("auth_epoch", "assoc_epoch"):
        raw = value.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return float(raw)
    return None


def analyzer_summary(result: dict[str, Any]) -> dict[str, Any]:
    structured = (
        result.get("structured") if isinstance(result.get("structured"), dict) else {}
    )
    roaming = (
        structured.get("roaming") if isinstance(structured.get("roaming"), dict) else {}
    )
    sequences = (
        roaming.get("sequences") if isinstance(roaming.get("sequences"), list) else None
    )
    if sequences is not None:
        stations = structured.get("station_logs") or {}
        station_rows = stations.get("stations") if isinstance(stations, dict) else []
        return {
            "roaming_total": len(sequences),
            "slow": sum(
                bool(item.get("is_slow"))
                for item in sequences
                if isinstance(item, dict)
            ),
            "decided": sum(
                item.get("slow_basis") is not None
                for item in sequences
                if isinstance(item, dict)
            ),
            "unmeasured": sum(
                item.get("slow_basis") is None
                for item in sequences
                if isinstance(item, dict)
            ),
            "sta_attached": sum(
                int(item.get("attached") or 0)
                for item in (station_rows or [])
                if isinstance(item, dict)
            ),
        }
    keys = ("roaming_total", "slow", "decided", "unmeasured", "sta_attached")
    return {key: result.get(key) for key in keys if key in result}


def compare_analyzer(
    result: dict[str, Any],
    transactions: list[RoamTransaction],
    sta_attached: int,
    tolerance_ms: float = DEFAULT_COMPARE_MS,
) -> dict[str, Any]:
    actual = {
        "roaming_total": len(transactions),
        "slow": sum(transaction.is_slow for transaction in transactions),
        "decided": sum(
            transaction.slow_basis is not None for transaction in transactions
        ),
        "unmeasured": sum(
            transaction.slow_basis is None for transaction in transactions
        ),
        "sta_attached": sta_attached,
    }
    expected = analyzer_summary(result)
    summary_diff = {
        key: {"analyzer": expected.get(key), "independent": actual.get(key)}
        for key in sorted(set(expected) | set(actual))
        if expected.get(key) != actual.get(key)
    }

    structured = (
        result.get("structured") if isinstance(result.get("structured"), dict) else {}
    )
    roaming = (
        structured.get("roaming") if isinstance(structured.get("roaming"), dict) else {}
    )
    sequences = (
        roaming.get("sequences") if isinstance(roaming.get("sequences"), list) else None
    )
    event_diff: dict[str, Any] = {}
    if sequences is not None:
        tolerance = tolerance_ms / 1000.0
        used: set[int] = set()
        analyzer_only = []
        field_mismatch = []
        for sequence in sequences:
            if not isinstance(sequence, dict):
                continue
            epoch = _event_epoch(sequence)
            candidates = [
                (index, transaction)
                for index, transaction in enumerate(transactions)
                if index not in used
                and transaction.sta == sequence.get("sta")
                and transaction.ap == sequence.get("ap")
                and epoch is not None
                and abs((_event_epoch(asdict(transaction)) or 0) - epoch) <= tolerance
            ]
            if not candidates:
                analyzer_only.append(sequence)
                continue
            index, transaction = min(
                candidates,
                key=lambda item: abs(
                    (_event_epoch(asdict(item[1])) or 0) - (epoch or 0)
                ),
            )
            used.add(index)
            analyzer_sta = sequence.get("sta_log") or {}
            analyzer_total = (
                analyzer_sta.get("total_ms") if isinstance(analyzer_sta, dict) else None
            )
            mismatches = {}
            if bool(sequence.get("is_slow")) != transaction.is_slow:
                mismatches["is_slow"] = [sequence.get("is_slow"), transaction.is_slow]
            if analyzer_total != transaction.sta_total_ms:
                mismatches["sta_total_ms"] = [analyzer_total, transaction.sta_total_ms]
            if mismatches:
                field_mismatch.append(
                    {
                        "analyzer": sequence,
                        "independent": asdict(transaction),
                        "fields": mismatches,
                    }
                )
        verifier_only = [
            asdict(transaction)
            for index, transaction in enumerate(transactions)
            if index not in used
        ]
        event_diff = {
            "analyzer_only": analyzer_only,
            "independent_only": verifier_only,
            "field_mismatch": field_mismatch,
        }
    clean = not summary_diff and all(not value for value in event_diff.values())
    return {
        "clean": clean,
        "analyzer": expected,
        "independent": actual,
        "summary_diff": summary_diff,
        "event_diff": event_diff,
    }


def build_report(
    sources: "OrderedDict[str, list[Path]]",
    station_paths: dict[str, Path],
    packet_counts: dict[str, int],
    offsets: dict[str, dict[str, Any]],
    merged_count: int,
    duplicates: int,
    transactions: list[RoamTransaction],
    packet_meta: dict[str, int],
    station_ledgers: dict[str, list[StationRoam]],
    bindings: dict[str, PairScore],
    binding_matrix: dict[str, dict[str, PairScore]],
    correlation: dict[str, Any],
    analyzer_comparison: Optional[dict[str, Any]],
    station_utc_offset: str,
    elapsed_sec: float,
) -> dict[str, Any]:
    sta_values = [
        float(transaction.sta_total_ms)
        for transaction in transactions
        if transaction.sta_total_ms is not None
    ]
    station_commands = sum(len(rows) for rows in station_ledgers.values())
    station_failed = sum(
        row.failed for rows in station_ledgers.values() for row in rows
    )
    station_summary = {
        name: {
            "path": str(station_paths[name]),
            "commands": len(rows),
            "success": sum(not row.failed for row in rows),
            "failed": sum(row.failed for row in rows),
            "slow_over_150ms": sum(
                row.total_ms is not None and row.total_ms > DEFAULT_STA_SLOW_MS
                for row in rows
            ),
        }
        for name, rows in station_ledgers.items()
    }
    return {
        "schema": "independent_roaming_verifier_v1",
        "independence": {
            "analyzer_imported": False,
            "packet_source": "tshark raw fields",
            "station_source": "wpa.log raw lines",
        },
        "inputs": {
            "sources": {
                tag: [str(path) for path in paths] for tag, paths in sources.items()
            },
            "stations": {name: str(path) for name, path in station_paths.items()},
            "station_utc_offset": station_utc_offset,
        },
        "alignment": offsets,
        "packet": {
            "filtered_by_source": packet_counts,
            "merged_filtered": merged_count,
            "cross_source_duplicates": duplicates,
            "station_macs": sorted({transaction.sta for transaction in transactions}),
            "roaming_total": len(transactions),
            "slow": sum(transaction.is_slow for transaction in transactions),
            "decided": sum(
                transaction.slow_basis is not None for transaction in transactions
            ),
            "unmeasured": sum(
                transaction.slow_basis is None for transaction in transactions
            ),
            **packet_meta,
        },
        "station_logs": {
            "commands": station_commands,
            "success": station_commands - station_failed,
            "failed": station_failed,
            "matched": correlation["matched"],
            "total_ms": {
                "count": len(sta_values),
                "min": min(sta_values) if sta_values else None,
                "p50": statistics.median(sta_values) if sta_values else None,
                "p95": _percentile(sta_values, 0.95),
                "max": max(sta_values) if sta_values else None,
                "slow_over_150ms": sum(
                    value > DEFAULT_STA_SLOW_MS for value in sta_values
                ),
            },
            "by_station": station_summary,
        },
        "bindings": {name: asdict(score) for name, score in bindings.items()},
        "binding_matrix": {
            name: {sta: asdict(score) for sta, score in scores.items()}
            for name, scores in binding_matrix.items()
        },
        "correlation": correlation,
        "analyzer_comparison": analyzer_comparison,
        "transactions": [asdict(transaction) for transaction in transactions],
        "elapsed_sec": round(elapsed_sec, 3),
    }


def render_markdown(report: dict[str, Any]) -> str:
    packet = report["packet"]
    station = report["station_logs"]
    lines = [
        "# 독립 로밍 검증 보고서",
        "",
        "분석기 모듈을 import하지 않고 tshark 원시 필드와 wpa.log 원문으로 생성했다.",
        "",
        "## 결과",
        "",
        "| 항목 | 값 |",
        "|---|---:|",
        f"| 패킷 로밍 | {packet['roaming_total']} |",
        f"| 느린 로밍 | {packet['slow']} |",
        f"| 판정 가능 | {packet['decided']} |",
        f"| 판정 불가 | {packet['unmeasured']} |",
        f"| STA 로그 명령 | {station['commands']} |",
        f"| STA 성공/실패 | {station['success']} / {station['failed']} |",
        f"| PCAP↔STA 매칭 | {station['matched']} |",
        f"| STA 체감 p50/p95 | {station['total_ms']['p50']} / {station['total_ms']['p95']} ms |",
        "",
        "## STA 바인딩",
        "",
        "| 로그 | STA MAC | offset | matched | residual MAD |",
        "|---|---|---:|---:|---:|",
    ]
    for name, binding in report["bindings"].items():
        lines.append(
            f"| {name} | {binding['sta']} | {binding['offset_sec']:.6f}s | "
            f"{binding['matched']} | {binding['residual_mad_ms']}ms |"
        )
    comparison = report.get("analyzer_comparison")
    if comparison is not None:
        lines.extend(
            [
                "",
                "## 분석기 비교",
                "",
                f"- 판정: **{'일치' if comparison['clean'] else '불일치'}**",
                f"- 요약 차이: `{json.dumps(comparison['summary_diff'], ensure_ascii=False)}`",
            ]
        )
    return "\n".join(lines) + "\n"


def _parse_assignment(values: list[str], label: str) -> "OrderedDict[str, list[Path]]":
    out: "OrderedDict[str, list[Path]]" = OrderedDict()
    for value in values:
        if "=" not in value:
            raise ValueError(f"{label} 형식은 NAME=PATH여야 한다: {value}")
        name, raw_path = value.split("=", 1)
        if not name.strip() or not raw_path.strip():
            raise ValueError(f"{label}의 NAME과 PATH는 비어 있을 수 없다: {value}")
        name = name.strip()
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise ValueError(f"파일이 없다: {path}")
        out.setdefault(name, []).append(path)
    return out


def _parse_bindings(values: list[str]) -> dict[str, str]:
    bindings = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"--bind 형식은 NAME=MAC이어야 한다: {value}")
        name, mac = value.split("=", 1)
        bindings[name] = mac.lower()
    return bindings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        action="append",
        required=True,
        metavar="TAG=PCAP",
        help="무선 관측점과 pcap. 같은 TAG를 반복하면 연속 조각으로 취급",
    )
    parser.add_argument(
        "--station",
        action="append",
        default=[],
        metavar="NAME=WPA_LOG",
        help="STA 이름과 wpa.log 경로",
    )
    parser.add_argument(
        "--bind",
        action="append",
        default=[],
        metavar="NAME=MAC",
        help="자동 STA 바인딩 대신 사용할 명시적 바인딩",
    )
    parser.add_argument("--reference", help="TSF 시각 기준 source TAG(기본: 첫 TAG)")
    parser.add_argument("--analyzer-result", type=Path, help="비교할 분석기 결과 JSON")
    parser.add_argument(
        "--output", type=Path, required=True, help="독립 검증 JSON 출력"
    )
    parser.add_argument("--markdown", type=Path, help="사람이 읽는 Markdown 출력")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument(
        "--station-utc-offset",
        default=DEFAULT_STATION_UTC_OFFSET,
        metavar="+09:00",
        help="wpa.log 현지시각의 UTC offset(기본: +09:00)",
    )
    parser.add_argument(
        "--strict", action="store_true", help="분석기와 불일치하면 exit 2"
    )
    parser.add_argument("--dedup-ms", type=float, default=DEFAULT_DEDUP_MS)
    parser.add_argument(
        "--assoc-attempt-ms", type=float, default=DEFAULT_ASSOC_ATTEMPT_MS
    )
    parser.add_argument("--sta-match-ms", type=float, default=DEFAULT_STA_MATCH_MS)
    parser.add_argument("--compare-ms", type=float, default=DEFAULT_COMPARE_MS)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    started = time.time()
    try:
        sources = _parse_assignment(args.source, "--source")
        station_groups = _parse_assignment(args.station, "--station")
        station_paths = {name: paths[0] for name, paths in station_groups.items()}
        if any(len(paths) != 1 for paths in station_groups.values()):
            raise ValueError("--station NAME에는 wpa.log 하나만 지정해야 한다")
        reference = args.reference or next(iter(sources))
        if reference not in sources:
            raise ValueError(f"--reference가 --source에 없다: {reference}")
        station_timezone = _parse_utc_offset(args.station_utc_offset)

        print("[1/6] tshark 로밍/EAPOL 전수 추출", file=sys.stderr)
        per_source, packet_counts = extract_packet_events(sources, args.tshark)
        print("[2/6] Beacon TSF 독립 시각 정렬", file=sys.stderr)
        beacons = extract_beacons(sources, args.tshark)
        offsets = estimate_tsf_offsets(beacons, reference)
        print("[3/6] 관측점 간 중복 제거 및 패킷 로밍 원장", file=sys.stderr)
        merged, duplicates = align_and_dedup(per_source, offsets, args.dedup_ms)
        sta_macs = detect_station_macs(merged)
        transactions, packet_meta = build_packet_ledger(
            merged, sta_macs, args.assoc_attempt_ms
        )
        print("[4/6] wpa.log ROAM→CONNECTED 원장", file=sys.stderr)
        station_ledgers = {
            name: parse_wpa_log(path, name, station_timezone)
            for name, path in station_paths.items()
        }
        explicit = _parse_bindings(args.bind) if args.bind else None
        bindings, matrix = bind_stations(
            station_ledgers, transactions, explicit, args.sta_match_ms
        )
        correlation = correlate_station_logs(
            station_ledgers, transactions, bindings, args.sta_match_ms
        )
        classify_transactions(transactions)
        print("[5/6] 분석기 결과 비교", file=sys.stderr)
        comparison = None
        if args.analyzer_result:
            analyzer_result = json.loads(
                args.analyzer_result.read_text(encoding="utf-8")
            )
            comparison = compare_analyzer(
                analyzer_result, transactions, correlation["matched"], args.compare_ms
            )
        report = build_report(
            sources=sources,
            station_paths=station_paths,
            packet_counts=packet_counts,
            offsets=offsets,
            merged_count=len(merged),
            duplicates=duplicates,
            transactions=transactions,
            packet_meta=packet_meta,
            station_ledgers=station_ledgers,
            bindings=bindings,
            binding_matrix=matrix,
            correlation=correlation,
            analyzer_comparison=comparison,
            station_utc_offset=args.station_utc_offset,
            elapsed_sec=time.time() - started,
        )
        print("[6/6] 결과 저장", file=sys.stderr)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        markdown = args.markdown or args.output.with_suffix(".md")
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(render_markdown(report), encoding="utf-8")
        print(render_markdown(report), end="")
        if args.strict and comparison is not None and not comparison["clean"]:
            return 2
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"검증 실패: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
