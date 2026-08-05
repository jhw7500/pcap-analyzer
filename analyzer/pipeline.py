"""분석 파이프라인 오케스트레이션 — CLI와 웹 모두 이 모듈을 호출한다."""
import hashlib
import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .core.extractor import extract_frames, extract_alignment_beacons, detect_tshark_version
from .core.channels import ap_channel_map
from .core.detector import detect_roles
from .core.indexer import FrameIndex
from .core.merge import merge_captures
from .core.timeparse import parse_local_epoch
from .core.wired_ping import build_ground_truth
from .core.modules import (
    overview, retry_mcs, retry_burst, roaming, ping_rtt,
    control_traffic, signal_quality, per_second,
    roaming_impact, ping_loss, diagnosis, eapol,
)
from .web.delay_analysis import analyze_delays
from .web.anomaly_frames import detect_anomalies
from .web.signal_cliff import analyze_signal_cliffs
from .web.evidence import build_debug_block
from .web.structured import (
    PING_MATCH_WINDOW_SEC,
    is_special_ip,
    _structured_overview,
    _structured_signal,
    _structured_ping,
    _structured_roaming,
    _structured_per_second,
    _structured_device_stats,
    _structured_system_stats,
    _structured_diagnosis,
    _structured_merge,
    _structured_sniffer_compare,
)

__all__ = [
    "run_analysis",
    "PING_MATCH_WINDOW_SEC",
    "_structured_overview",
    "_structured_signal",
    "_structured_ping",
    "_structured_roaming",
    "_structured_per_second",
    "_structured_device_stats",
    "_structured_system_stats",
    "_structured_diagnosis",
    "_structured_merge",
    "_structured_sniffer_compare",
]

#: 프레임을 하나도 못 뽑았을 때(추출 실패 또는 시간 창 적용 후 0건) 공통 에러 메시지.
_NO_FRAMES_ERROR = "프레임을 추출하지 못했습니다. tshark 경로 또는 pcap 파일을 확인하세요."


def _make_id(pcap_path: str) -> str:
    ts = int(time.time())
    name = Path(pcap_path).stem
    h = hashlib.md5(pcap_path.encode()).hexdigest()[:8]
    return f"{ts}_{name}_{h}"


def _derived_ip_filter(frames, mac_filter: str) -> str:
    """mac_filter 대상 STA가 **자기 IP로 쓴 주소**들을 유선 GT용 ip_filter 문자열로.

    mac_filter는 유선(비-802.11) 캡처에 MAC 개념이 없어 그대로 넘길 수 없다. 대신
    필터 대상 STA의 IP를 유도해 넘기면 유선 GT도 같은 모집단을 본다 — 그러지 않으면
    무선은 특정 STA만, 유선은 sender의 모든 target을 집계해 GT 카드가 서로 다른
    모집단을 비교하고 필터 밖 target의 streak가 전체 기준 진단으로 폴백한다.

    "프레임에 보이는 모든 IP"가 아니라 **대상 STA 자신의 IP**만 모으는 이유: 유선
    GT의 sender(ping을 보낸 호스트) IP까지 목록에 들어가면 wired_ping의
    `_filter_exchanges`가 "sender가 필터에 있으면 전체 유지"(무선 `ip.addr ==`
    대칭 규칙) 경로를 타서 다른 target들이 그대로 남는다 — 모집단이 다시 어긋난다.
    대상 STA의 IP만 넘기면 그 STA와의 ping만 남는다. sender가 곧 그 STA인 직접
    토폴로지에서는 그 IP가 sender라 전체 유지가 되는데, 그 경우엔 그게 정확한
    모집단이다(그 STA가 보낸 모든 ping).

    자기 IP 판정은 `_structured_overview`의 dev_ip 수집과 같은 규칙 — 그 STA가
    송신(ta)한 프레임의 ip.src, 수신(ra)한 프레임의 ip.dst. tshark는 같은 필드의
    multi-value를 콤마로 join해 주므로 콤마로 분해한다. 멀티캐스트/링크로컬/루프백/
    브로드캐스트/미지정 주소는 `structured.is_special_ip`(같은 규칙을 공유 —
    `_structured_overview`의 자기 IP 후보 필터와 동일한 정의를 써야 두 경로가
    "특수 IP"를 다르게 취급하지 않는다)로 제외한다. 유도된 IP가 하나도 없으면
    빈 문자열 — 호출부가 "동등 필터 유도 불가"로 처리한다.
    """
    macs = {m.strip().lower() for m in mac_filter.split(",") if m.strip()}
    if not macs:
        return ""
    ips = set()
    for f in frames:
        for mac, raw in ((f.ta, f.ip_src), (f.ra, f.ip_dst)):
            if (mac or "").lower() not in macs:
                continue
            for ip in (raw or "").split(","):
                ip = ip.strip()
                if ip and not is_special_ip(ip):
                    ips.add(ip)
    return ",".join(sorted(ips))


def run_analysis(
    pcap_path: str,
    ssid: str = "",
    passphrase: str = "",
    time_start: str = "",
    time_end: str = "",
    mac_filter: str = "",
    ip_filter: str = "",
    wireless_paths: Optional[List[str]] = None,
    wired_path: str = "",
    progress_cb: Optional[Callable[[str, int], None]] = None,
    cancel_event: Optional[Any] = None,
) -> Dict[str, Any]:
    """전체 분석 파이프라인 실행. 구조화된 결과를 반환."""

    def _cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    def _progress(msg: str, pct: int = 0):
        if progress_cb:
            progress_cb(msg, pct)

    if _cancelled():
        return {"cancelled": True}

    _progress("tshark로 프레임 추출 중...", 10)
    import config as _config
    import time as _time
    _tshark_path = _config.detect_tshark()
    _tshark_info = detect_tshark_version(_tshark_path or "tshark")

    # 추출 진행률: 시간·프레임 수에 따라 10→28%로 점진 (asymptotic, 절대 30 초과 안함)
    _extract_t0 = _time.time()
    def _frame_progress(count):
        elapsed = _time.time() - _extract_t0
        # 시간 기반 0~18% 추가 (60초쯤 12%, 5분쯤 17%)
        pct = 10 + int(18 * (1 - 1 / (1 + elapsed / 30)))
        _progress(f"tshark 추출... {count:,}프레임 처리됨", min(pct, 28))

    # pcap_path가 기준(w1), wireless_paths는 추가 무선(w2, w3, …) — 파일별로
    # extract_frames를 동일 필터 인자로 호출한다(필터 대칭 자동으로 확보됨).
    paths = [pcap_path] + list(wireless_paths or [])
    tags = [f"w{i + 1}" for i in range(len(paths))]

    # 다중 무선 + 시간 필터: 파일별 tshark 추출에 같은 time_start/time_end를 그대로
    # 넘기면 캡처 간 시계 스큐(수십~수백 초까지 가능 — merge.py 실측 근거)만큼
    # 소스마다 실제로 다른 구간이 잘려, 시계 정렬에 쓸 공통 TSF 비콘이 통째로
    # 사라질 수 있다(오프셋 추정 실패 또는 소스 제외 — PR #23 리뷰 Finding A).
    # 다중 무선일 때는 정렬에 충분한 전체 구간을 먼저 추출해 merge(오프셋
    # 추정·보정)한 뒤, 보정된 epoch 위에서 요청 구간을 사후 적용한다. 단일 무선
    # 경로는 비교 대상 스큐가 없어 기존처럼 추출 시 tshark 필터로 자른다(하위
    # 호환). mac_filter/ip_filter는 프레임 내용 기반이라 스큐와 무관 — 다중
    # 무선에서도 추출 시 그대로 유지한다(대칭 필터 보장).
    multi_wireless = len(paths) > 1
    defer_time_window = multi_wireless and bool(time_start or time_end)

    window_start_epoch: Optional[float] = None
    window_end_epoch: Optional[float] = None
    if defer_time_window:
        # 무선 extractor.build_tshark_cmd의 `frame.time >= "..."` 필터와 같은
        # 규칙(로컬 타임존, 초 생략 허용)으로 파싱해야 두 경로가 같은 구간을
        # 가리킨다 — wired_ping._parse_local_epoch와 공유하는 timeparse 헬퍼.
        # 파싱 실패는 기존 tshark 필터 방식과 동일하게 명시적 에러로 반환한다
        # (조용히 전체 구간으로 넘어가지 않는다).
        if time_start:
            window_start_epoch = parse_local_epoch(time_start)
            if window_start_epoch is None:
                # error_code: 호출부(routes/upload.py)가 이 값이 있으면 일괄
                # NO_FRAMES(500)로 뭉개지 않고 전용 코드(400, 사용자 입력
                # 정정 유도)로 표면화한다(PR #23 리뷰 6라운드 Finding A).
                # "error" 문자열은 CLI(analyze-cli.py) 그대로 출력을 위해 유지.
                return {
                    "error": f"시간 필터를 해석할 수 없다: {time_start}",
                    "error_code": "INVALID_TIME_FILTER",
                }
        if time_end:
            window_end_epoch = parse_local_epoch(time_end)
            if window_end_epoch is None:
                return {
                    "error": f"시간 필터를 해석할 수 없다: {time_end}",
                    "error_code": "INVALID_TIME_FILTER",
                }

    extract_time_start = "" if defer_time_window else time_start
    extract_time_end = "" if defer_time_window else time_end

    # 다중 무선 + 내용 필터(mac_filter/ip_filter): 본 추출(pass-2, 아래)에
    # 걸리는 이 필터들은 비콘을 통째로 지울 수 있다 — STA mac_filter는
    # 비콘에 STA 주소가 없어서, ip_filter는 비콘에 IP가 없어서 매칭되지
    # 않는다. 비콘이 사라지면 merge.py의 TSF 정렬 증거가 없어지고 ±5초 seq
    # 폴백도 큰 스큐(실측 183초)엔 무력하다(PR #23 리뷰 2라운드 Finding A).
    # 이때만 pass-1로 각 무선 파일의 비콘을 필터 없이 따로 뽑아
    # merge_captures(alignment_sources=...)의 오프셋 추정 전용 입력으로
    # 쓴다. 단일 무선은 비교 대상 스큐가 없어 정렬 자체가 불필요하므로 제외.
    need_alignment_pass = multi_wireless and bool(mac_filter or ip_filter)
    alignment_sources: Optional["OrderedDict[str, list]"] = (
        OrderedDict() if need_alignment_pass else None
    )

    per_source: "OrderedDict[str, list]" = OrderedDict()
    wireless_sources: List[Dict[str, Any]] = []
    for i, (path, tag) in enumerate(zip(paths, tags)):
        if _cancelled():
            return {"cancelled": True}
        if len(paths) > 1:
            _progress(f"tshark로 프레임 추출 중... ({i + 1}/{len(paths)})",
                      10 + int(18 * i / len(paths)))
        if need_alignment_pass:
            align_frames = extract_alignment_beacons(
                path, tshark_path=_tshark_path, cancel_event=cancel_event,
            )
            for f in align_frames:
                f.source = tag
            alignment_sources[tag] = align_frames
            if _cancelled():
                return {"cancelled": True}
        file_frames = extract_frames(
            path,
            wpa_passphrase=passphrase,
            ssid=ssid,
            time_start=extract_time_start,
            time_end=extract_time_end,
            mac_filter=mac_filter,
            ip_filter=ip_filter,
            tshark_path=_tshark_path,
            cancel_event=cancel_event,
            progress_cb=_frame_progress,
        )
        for f in file_frames:
            f.source = tag
        src_entry = {
            "name": Path(path).name, "role": "wireless",
            "frame_count": len(file_frames), "warnings": [],
        }
        if len(paths) > 1:
            # tag는 프론트가 sniffer_compare/배지와 sources를 조인하는 키 —
            # 단일 업로드 결과의 직렬화를 바꾸지 않도록 다중일 때만 싣는다.
            src_entry["tag"] = tag
        if file_frames:
            per_source[tag] = file_frames
        else:
            src_entry["warnings"].append(
                f"{Path(path).name}: 802.11 프레임이 0건이라 병합에서 제외됨"
            )
        wireless_sources.append(src_entry)

    if not per_source:
        return {"error": _NO_FRAMES_ERROR}

    if _cancelled():
        return {"cancelled": True}

    # 다중 소스면 시계 정렬 후 dedup·재번호해 단일 타임라인으로 병합한다. 단일
    # 소스(원래 1개 경로만 준 경우든, 나머지가 0건이라 걸러진 경우든)는 merge를
    # 아예 호출하지 않아 기존 파이프라인과 완전히 동일한 결과를 낸다(하위 호환).
    merge_summary: Optional[Dict[str, Any]] = None
    sniffer_summary: Optional[Dict[str, Any]] = None
    # 다중 경로 입력 + 내용 필터(alignment_sources가 존재 — need_alignment_pass)면,
    # 생존 소스 수와 무관하게 항상 기준을 "w1"로 명시해 merge_captures를
    # 호출한다. mac_filter/ip_filter가 secondary에서만 매칭되면 w1(기준)이
    # 0건으로 제외돼 생존 소스가 1개("w2" 등)뿐일 수 있는데, 그 경우에도
    # merge를 건너뛰면(구 동작) 그 소스는 원시(미보정) 시계 그대로 남는다 —
    # 이미 연기해 둔 시간 창(사용자의 실제 벽시계 기준)이 그 미보정 epoch에
    # 적용돼 스큐(문서화된 최대 183s)만큼 구간이 어긋나거나 NO_FRAMES로
    # 붕괴할 수 있다(PR #23 리뷰 3라운드 Finding A). merge_captures가
    # alignment_sources["w1"](내용 필터 없이 뽑은 비콘)를 기준으로 그 생존
    # 소스의 오프셋을 추정·적용해준다 — 정렬 증거 자체도 없으면(극단적으로
    # 드묾) estimate_offset이 자연히 "none"으로 떨어져 기존과 동일하게
    # 원시 시계로 병합된다. alignment pass가 없으면(내용 필터 없음) 이
    # 조건이 아예 성립하지 않고, 그 경우 w1이 0건이 되는 유일한 이유는
    # 캡처 자체가 비었기 때문이므로(시간 필터는 다중 무선일 때 이미 연기돼
    # pass-2도 전체 구간을 보므로) 기존 동작(생존 1개면 merge 생략)이 여전히
    # 타당하다.
    run_merge = len(per_source) > 1 or alignment_sources is not None
    if run_merge:
        merge_reference_tag = "w1" if alignment_sources is not None else None
        mr = merge_captures(
            per_source, alignment_sources=alignment_sources, reference_tag=merge_reference_tag,
        )
        frames = mr.frames
        reference_tag = merge_reference_tag or next(iter(per_source))
        # mr.warnings는 merge_captures가 tags[1:]를 같은 순서로 순회하며 소스별
        # (off.warnings + "none"이면 tag별 문구) 블록을 이어 붙인 것이다 — 아래
        # 루프도 정확히 같은 소스 순서·같은 구성으로 tag_warnings를 재구성하므로,
        # 문자열 값으로 remove()하지 않고 소비한 길이만큼 앞에서 잘라낸다. 값
        # 기반 remove()는 여러 소스가 동일한 경고 문자열(예: "none" 공통 문구)을
        # 낼 때 어떤 소스의 몫을 지우는지 보장이 없어 오귀속 위험이 있었다
        # (PR #23 리뷰 2라운드 Finding E-2).
        remaining_warnings = list(mr.warnings)
        consumed = 0
        for tag, src_entry in zip(tags, wireless_sources):
            if tag not in per_source:
                continue
            if tag == reference_tag:
                src_entry["applied_offset_ms"] = 0.0
                src_entry["offset_method"] = "reference"
                continue
            off = mr.offsets[tag]
            src_entry["applied_offset_ms"] = round(off.offset_sec * 1000, 3)
            src_entry["offset_method"] = off.method
            src_entry["offset_pairs"] = off.pairs  # 프론트 신뢰도 표기용(비콘 TSF 매칭 쌍 수)
            tag_warnings = list(off.warnings)
            if off.method == "none":
                tag_warnings.append(f"{tag}: 오프셋 추정 실패 — 원시 시계 그대로 병합됨")
            consumed += len(tag_warnings)
            src_entry["warnings"] = src_entry["warnings"] + tag_warnings
        remaining_warnings = remaining_warnings[consumed:]
        # 소스별로 귀속되지 않은 나머지 경고(향후 일반 경고 확장 대비)는 기준(w1)에 붙인다.
        if remaining_warnings:
            wireless_sources[0]["warnings"] = wireless_sources[0]["warnings"] + remaining_warnings
        # structured["merge"] 스키마 생성은 웹 시각화 소관(analyzer/web/structured.py) —
        # pipeline은 오케스트레이션만 담당한다(AGENTS.md, PR #23 리뷰 Finding B).
        # sources 배열의 오프셋 필드(applied_offset_ms 등, 위)는 구조화 스키마가
        # 아니라 소스 메타데이터라 이 경계 밖 — pipeline에 남는다.
        merge_summary = _structured_merge(mr)
        sniffer_summary = _structured_sniffer_compare(mr)
    else:
        (frames,) = per_source.values()

    # 다중 무선 + 시간 필터를 미룬 경우: 시계 정렬·보정이 끝난 epoch 위에서 이제야
    # 요청 구간을 적용한다(PR #23 리뷰 Finding A). merge_summary(및 mr.stats)는
    # 이미 위에서 창 적용 전 값으로 고정됐다 — 정렬·dedup은 항상 전체 구간
    # 기준이 맞기 때문에 창 이후 재계산하지 않는다.
    if defer_time_window:
        frames = [
            f for f in frames
            if (window_start_epoch is None or f.epoch >= window_start_epoch)
            and (window_end_epoch is None or f.epoch < window_end_epoch)
        ]
        if not frames:
            return {"error": _NO_FRAMES_ERROR}

    _progress(f"{len(frames):,}프레임 추출 완료. 역할 감지 중...", 30)
    roles = detect_roles(frames)

    if _cancelled():
        return {"cancelled": True}

    _progress("프레임 인덱싱 중...", 40)
    index = FrameIndex(frames, roles)

    _progress("분석 모듈 실행 중...", 50)

    # 텍스트 섹션 (기존 호환)
    analyzer_list = [
        ("개요", overview),
        ("Retry MCS", retry_mcs),
        ("Retry Burst", retry_burst),
        ("로밍", roaming),
        ("Ping RTT", ping_rtt),
        ("제어 트래픽", control_traffic),
        ("신호 품질", signal_quality),
        ("초당 통계", per_second),
        ("로밍 영향", roaming_impact),
        ("Ping Loss", ping_loss),
        ("종합 진단", diagnosis),
    ]
    text_sections = []
    for i, (name, mod) in enumerate(analyzer_list):
        if _cancelled():
            return {"cancelled": True}
        _progress(f"{name} 분석...", 50 + int(40 * i / len(analyzer_list)))
        text_sections.append(mod.analyze(frames, roles, index))

    # 구조화된 데이터 (웹 시각화용) — 90→99% 단계별 진행
    overview_section = text_sections[0]
    structured: Dict[str, Any] = {}
    if merge_summary is not None:
        structured["merge"] = merge_summary
    if sniffer_summary is not None:
        structured["sniffer_compare"] = sniffer_summary

    _progress("시각화: 개요 데이터 생성 중...", 90)
    # AP 채널 맵은 프레임 전수 조사(O(N)) — overview/roaming이 재사용하도록 1회만 계산
    _ap_ch = ap_channel_map(frames, roles)
    structured["overview"] = _structured_overview(
        frames, roles, overview_section, ap_ch=_ap_ch
    )
    if _cancelled():
        return {"cancelled": True}

    _progress("시각화: 신호 품질 데이터 생성 중...", 91)
    structured["signal"] = _structured_signal(frames, roles, index)
    if _cancelled():
        return {"cancelled": True}

    _progress("시각화: Ping 데이터 생성 중...", 93)
    structured["ping"] = _structured_ping(frames, roles)
    if _cancelled():
        return {"cancelled": True}

    # 입력 파일 메타 — 유선 ground truth가 있으면 ping에 부착 (스펙 §4·§6)
    sources = list(wireless_sources)
    if wired_path:
        _progress("유선 ground truth 분석 중...", 93)
        # time_start/end·ip_filter는 무선 extract_frames()와 동일 구간을 보도록
        # 대칭 전달 — 그래야 유선 GT와 무선 관측이 같은 구간을 비교한다.
        # mac_filter는 유선(비-802.11) exchange에 MAC 개념이 없어 그대로 못 넘기므로,
        # 이미 필터가 적용된 무선 프레임의 IP로 동등한 ip_filter를 유도해 별도 인자
        # (derived_ip_filter)로 전달한다. 사용자 ip_filter는 **항상 그대로** 전달하고
        # (10라운드처럼 유도값으로 대체하지 않는다), build_ground_truth 내부에서 두
        # 필터를 독립적으로 순차 적용해 AND로 결합한다 (PR #22 11라운드 — Finding A).
        # 대체 방식(10라운드)의 결함: 직접 토폴로지(mac_filter 대상 STA == sender)에서
        # 유도값은 sender 자신의 IP다 — 이 값이 사용자가 명시한 target-only ip_filter를
        # 덮어쓰면, 유선 `_filter_exchanges`의 "sender가 필터에 있으면 전체 유지"
        # 경로를 타 사용자가 원한 target 좁히기가 사라진다. 병행(AND) 방식에서는 사용자
        # 필터가 narrowing을 맡고 derived 필터(sender 포함)는 무해한 no-op이 되어
        # 두 토폴로지(직접/상류) 모두 옳다 — 자세한 근거는 wired_ping.build_ground_truth
        # docstring 참조.
        wired_derived_filter, skip_reason = "", ""
        if mac_filter:
            derived = _derived_ip_filter(frames, mac_filter)
            if derived:
                wired_derived_filter = derived
            else:
                # 유도 실패(미해독 캡처 등) — 다른 모집단을 비교하느니 생략한다.
                skip_reason = (
                    "mac_filter와 동등한 유선 필터를 유도할 수 없어 ground truth 를 "
                    "생략했다 (무선 프레임에서 대상 STA의 IP를 찾지 못함)"
                )
        if skip_reason:
            sources.append({
                "name": Path(wired_path).name, "role": "wired",
                "frame_count": None, "warnings": [skip_reason],
            })
        else:
            gt = build_ground_truth(
                wired_path,
                tshark_path=_tshark_path or "tshark",
                time_start=time_start,
                time_end=time_end,
                ip_filter=ip_filter,
                derived_ip_filter=wired_derived_filter,
                cancel_event=cancel_event,
            )
            if gt.get("cancelled"):
                return {"cancelled": True}
            wired_src = {
                "name": Path(wired_path).name, "role": "wired",
                "frame_count": None, "warnings": list(gt.get("warnings", [])),
            }
            if "error" in gt:
                wired_src["warnings"].append(gt["error"])
            else:
                structured.setdefault("ping", {})["ground_truth"] = gt
            sources.append(wired_src)
    structured["sources"] = sources
    if _cancelled():
        return {"cancelled": True}

    _progress("시각화: EAPOL 4-way 분석 중...", 94)
    structured["eapol"] = eapol.build_handshakes(frames, roles)
    if _cancelled():
        return {"cancelled": True}

    _progress("시각화: 로밍 데이터 생성 중...", 94)
    structured["roaming"] = _structured_roaming(
        frames,
        roles,
        handshakes=structured["eapol"].get("handshakes", []),
        ap_ch=_ap_ch,
    )
    if _cancelled():
        return {"cancelled": True}

    _progress("시각화: 초당 통계 생성 중...", 95)
    structured["per_second"] = _structured_per_second(frames)
    if _cancelled():
        return {"cancelled": True}

    _progress("시각화: 장치별 통계 생성 중...", 96)
    structured["device_stats"] = _structured_device_stats(frames, roles, index)
    structured["system_stats"] = _structured_system_stats(frames, index)
    if _cancelled():
        return {"cancelled": True}

    _progress("지연/이상/신호절벽 분석 중...", 98)
    structured["delay_zones"] = analyze_delays(structured["ping"], structured["roaming"], structured["per_second"])
    structured["anomaly_frames"] = detect_anomalies(structured["overview"])
    structured["signal_cliffs"] = analyze_signal_cliffs(structured["signal"])

    _progress("종합 진단 생성 중...", 99)
    structured["diagnosis"] = _structured_diagnosis(structured, frames, index)

    # 디버그 타임라인용 증거 블록 (공유 시간축 + 다운샘플 시계열 + 근거 프레임)
    structured["debug"] = build_debug_block(structured, frames, index, roles)

    # 텍스트 리포트 (호환용)
    text_report = []
    for sec in text_sections:
        text_report.append({"title": sec.title, "summary": sec.summary, "lines": sec.lines})

    _progress("완료!", 100)
    return {
        "id": _make_id(pcap_path),
        "pcap_name": Path(pcap_path).name,
        "pcap_size": os.path.getsize(pcap_path),
        "frame_count": len(frames),
        # 호스트 로컬 시각 + 시간대(%Z, 예: KST) — 리포트의 UTC 기반 이벤트
        # 시각(_format_epoch)과 혼동하지 않게 시간대를 함께 기록. 시간대 없는
        # 구버전 값은 report.py가 '(호스트 로컬 시각)'으로 표기한다.
        "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "tshark_version": _tshark_info["version"],
        "tshark_path": _tshark_info["path"],
        "structured": structured,
        "text_sections": text_report,
    }
