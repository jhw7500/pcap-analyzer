"""STA(스테이션) 로그 파싱 — pcap이 못 보는 로밍 구간을 복원한다.

pcap은 **전파에 실제로 나온 프레임**만 본다. 실측(2시간 캡처)으로 로밍 전체를
쪼개면 pcap이 보는 구간은 `Auth 요청 → 4-way 완료` 25.2ms인데, STA 자신이 겪는
로밍(`ROAM 명령 → CONNECTED`)은 96.5ms다 — **74%가 전파 밖**이다. 스캔·로밍 판단·
드라이버 상태 전이·키 설치가 그 안에 있고, 그건 STA 로그에만 남는다.

## 다루는 로그 3종 (호기 = STA 1대당 한 세트)
- ``wpa.log``    wpa_supplicant 상태 전이 — 로밍 에피소드의 시작/끝 경계
- ``kern.log``   커널 wlan 드라이버 — 스캔 시작/완료, STA 자기 IP(매칭 열쇠)
- ``logger.log`` 로밍 데몬(wifi_roam.py) — **왜** 로밍했는지(임계·후보·점수)

## 공통 줄 포맷
``2026-07-23 08:50:07.855 wpa_supplicant[info] mlan0: Event SCAN_STARTED (47) received``
= ``<벽시계 ms> <프로세스>[<레벨>] <메시지>``. 타임존이 없는 naive local time이라
pcap epoch과 맞추려면 **반드시 오프셋 보정**이 필요하다(`station_match` 참조).
"""
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

#: 모든 로그 공통 앞머리. 프로세스/레벨은 파일마다 다르므로 named group으로 뽑는다
#: (`mlan0:` 같은 인터페이스 접두는 메시지 쪽에서 처리 — 하드코딩하면 p2p-dev-mlan0
#: 등 다른 인터페이스가 섞일 때 즉시 깨진다).
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<proc>\S+?)\[(?P<level>\w+)\]\s*(?P<rest>.*)$"
)

#: 인터페이스 접두(`mlan0: `). 없을 수도 있다(kern.log의 일부 줄).
_IFACE_RE = re.compile(r"^(?P<iface>[A-Za-z0-9_.-]+):\s*(?P<msg>.*)$")

_MAC = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"

# ── wpa.log ────────────────────────────────────────────────────────────────
#: 로밍 **시작** 앵커. 이 환경의 로밍은 외부 데몬이 밀어넣는 강제 로밍이라
#: ROAM 명령 시각이 명확한 t0다. 실측 호기당 정확히 306건.
_WPA_ROAM_CMD = re.compile(rf"Control interface command 'ROAM (?P<bssid>{_MAC})'")
#: 로밍 **종료** 앵커. 주의: 전체 건수는 307로 ROAM(306)보다 1 많다 —
#: 마지막 1건은 ROAM 명령 없는 자동 재접속이라 CONNECTED로 로밍을 세면 과대계상된다.
_WPA_CONNECTED = re.compile(rf"CTRL-EVENT-CONNECTED - Connection to (?P<bssid>{_MAC})")
_WPA_DISCONNECTED = re.compile(rf"CTRL-EVENT-DISCONNECTED bssid=(?P<bssid>{_MAC}) reason=(?P<reason>\d+)")
_WPA_STATE = re.compile(r"State: (?P<from>[A-Z_0-9]+) -> (?P<to>[A-Z_0-9]+)")
_WPA_EVENT = re.compile(r"Event (?P<name>[A-Z_]+) \((?P<code>\d+)\) received")

#: 로밍이 실패로 끝났음을 나타내는 상태 전이(성공 경로엔 없다).
_FAIL_STATES = {"DISCONNECTED", "SCANNING", "INACTIVE"}

# ── kern.log ───────────────────────────────────────────────────────────────
#: 커널 monotonic 타임스탬프(부팅 후 초). 호기마다 기준이 달라 **호기 간 비교 금지** —
#: 구간 소요는 벽시계 지터(±수백 ms)를 피해 이 값으로 재고, pcap 정렬만 벽시계로 한다.
_KERN_MONO = re.compile(r"\[(?P<mono>\d+\.\d+)\]")
_KERN_SCAN_START = re.compile(r"wlan:\s*(?P<iface>\S+)\s+START SCAN")
_KERN_SCAN_DONE = re.compile(r"wlan:\s*SCAN COMPLETED: scanned AP count=(?P<count>\d+)")
#: STA 자기 IP — 로그 폴더 ↔ pcap STA를 잇는 유일하게 신뢰 가능한 조인 키.
#: **절반이 0.0.0.0**이다(로밍마다 `0.0.0.0 → 실IP` 쌍). 필터 없이 첫 값을 쓰면
#: 모든 호기가 0.0.0.0으로 나와 매칭이 전멸한다.
_KERN_IP = re.compile(r"bridge:\s*wlan IPv4 updated\s*=\s*(?P<ip>\d+\.\d+\.\d+\.\d+)")

# ── logger.log ─────────────────────────────────────────────────────────────
_LOG_ROAMING = re.compile(rf"Roaming:\s*(?P<from>{_MAC})\s*→\s*(?P<to>{_MAC})")
_LOG_CONFIRMED = re.compile(rf"Roam successful \(confirmed\):\s*(?P<bssid>{_MAC})")
_LOG_CANDIDATE = re.compile(
    rf"Roam candidate:\s*(?P<bssid>{_MAC}),\s*rssi=(?P<rssi>-?\d+)dB"
    r"(?:\s*\(diff=(?P<diff>-?\d+)dB\))?.*?reason=(?P<reason>[^,]+),\s*score=(?P<score>[\d.]+)"
)
_LOG_CONDITION = re.compile(
    r"roaming condition:\s*(?P<rssi>-?\d+)\s*<\s*(?P<th>-?\d+)"
    r"\s*\(base=(?P<base>-?\d+),\s*trend=(?P<trend>\w+)\)"
)
_LOG_SKIP = re.compile(r"Roam (?P<kind>skipped)|No suitable roam candidate")

#: 같은 로밍이 wifi_roam.py의 두 지점에서 각각 로그를 남긴다(실측 간격 0~2ms).
#: 이 시간 안에 같은 (from, to)가 다시 오면 중복으로 본다.
_SAME_ROAM_LOG_SEC = 0.5


def _parse_ts(raw: str) -> float:
    """'2026-07-23 08:50:07.855' → epoch(초). 로컬 타임존 기준(로그에 TZ 없음)."""
    return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f").timestamp()


@dataclass
class LogLine:
    epoch: float
    proc: str
    level: str
    iface: str
    msg: str
    mono: Optional[float] = None   #: kern.log의 커널 monotonic 초


def parse_lines(path: str) -> List[LogLine]:
    """로그 파일을 공통 줄 구조로 파싱. 형식이 안 맞는 줄은 조용히 건너뛴다.

    실측 3개 호기 × 3개 파일에서 파싱 실패 0줄이지만, 다른 장비/버전에서
    형식이 다를 수 있으므로 예외를 던지지 않는다(부분 파싱이 전무보다 낫다).
    """
    out: List[LogLine] = []
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return out
    with fh:
        for raw in fh:
            m = _LINE_RE.match(raw.rstrip("\n"))
            if not m:
                continue
            rest = m.group("rest")
            iface = ""
            im = _IFACE_RE.match(rest)
            if im:
                iface, rest = im.group("iface"), im.group("msg")
            mono = None
            mm = _KERN_MONO.search(rest)
            if mm:
                try:
                    mono = float(mm.group("mono"))
                except ValueError:
                    mono = None
            try:
                epoch = _parse_ts(m.group("ts"))
            except ValueError:
                continue
            out.append(LogLine(epoch, m.group("proc"), m.group("level"), iface, rest, mono))
    return out


@dataclass
class RoamEpisode:
    """wpa.log에서 잘라낸 로밍 1건 (STA 관점)."""
    cmd_epoch: float                    #: ROAM 명령 (로밍 의도 시각 = t0)
    target_bssid: str
    connected_epoch: Optional[float] = None   #: CTRL-EVENT-CONNECTED (링크 업)
    connected_bssid: str = ""
    states: List[Tuple[float, str, str]] = field(default_factory=list)
    events: List[Tuple[float, str]] = field(default_factory=list)
    failed: bool = False
    fail_reason: str = ""

    @property
    def total_ms(self) -> Optional[float]:
        """ROAM 명령 → CONNECTED. STA가 체감하는 로밍 전체 소요."""
        if self.connected_epoch is None:
            return None
        return (self.connected_epoch - self.cmd_epoch) * 1000

    def state_epoch(self, to_state: str) -> Optional[float]:
        for ep, _frm, to in self.states:
            if to == to_state:
                return ep
        return None

    @property
    def assoc_procedure_ms(self) -> Optional[float]:
        """AUTHENTICATING 진입 → CONNECTED. pcap 전파구간과 가장 가까운 범위."""
        a = self.state_epoch("AUTHENTICATING")
        if a is None or self.connected_epoch is None:
            return None
        return (self.connected_epoch - a) * 1000


def parse_wpa_log(path: str) -> List[RoamEpisode]:
    """wpa.log에서 로밍 에피소드를 잘라낸다.

    경계 규칙: **시작 = `ROAM <bssid>` 명령**, **끝 = 그 뒤 첫 CONNECTED**.
    - CONNECTED로 세지 않는 이유: 총 307건 중 1건은 ROAM 없는 자동 재접속이라
      로밍 수가 과대계상된다(실측 3개 호기 전부 동일).
    - 고정 줄 수(성공 시 18줄) 슬라이스는 쓰지 않는다 — 실패 로밍은 그 길이가
      아니고, 에피소드 사이 filler 줄 수도 2~8줄로 변한다.
    - 다음 ROAM 명령을 만나면 그 전에 CONNECTED가 없었다는 뜻이므로 실패로 닫는다.
    """
    lines = parse_lines(path)
    eps: List[RoamEpisode] = []
    cur: Optional[RoamEpisode] = None

    def _close_failed(reason: str) -> None:
        nonlocal cur
        if cur is not None:
            cur.failed = True
            cur.fail_reason = reason
            eps.append(cur)
            cur = None

    for ln in lines:
        m = _WPA_ROAM_CMD.search(ln.msg)
        if m:
            _close_failed("다음 ROAM 명령 전까지 CONNECTED 없음")
            cur = RoamEpisode(cmd_epoch=ln.epoch, target_bssid=m.group("bssid").lower())
            continue
        if cur is None:
            continue
        sm = _WPA_STATE.search(ln.msg)
        if sm:
            cur.states.append((ln.epoch, sm.group("from"), sm.group("to")))
            if sm.group("to") in _FAIL_STATES:
                _close_failed(f"상태 전이 {sm.group('from')} → {sm.group('to')}")
                continue
        em = _WPA_EVENT.search(ln.msg)
        if em:
            name = em.group("name")
            cur.events.append((ln.epoch, name))
            if name == "AUTH_TIMED_OUT":
                _close_failed("AUTH_TIMED_OUT")
                continue
        cm = _WPA_CONNECTED.search(ln.msg)
        if cm:
            cur.connected_epoch = ln.epoch
            cur.connected_bssid = cm.group("bssid").lower()
            eps.append(cur)
            cur = None
    _close_failed("로그 끝까지 CONNECTED 없음")
    return eps


@dataclass
class ScanPair:
    """kern.log의 스캔 1회 (START → COMPLETED)."""
    start_epoch: float
    done_epoch: float
    ap_count: int
    start_mono: Optional[float] = None
    done_mono: Optional[float] = None

    @property
    def duration_ms(self) -> float:
        """스캔 소요. monotonic이 둘 다 있으면 그걸 쓴다 — 벽시계는 지터가 크다."""
        if self.start_mono is not None and self.done_mono is not None:
            return (self.done_mono - self.start_mono) * 1000
        return (self.done_epoch - self.start_epoch) * 1000


def parse_kern_log(path: str) -> Dict[str, Any]:
    """kern.log에서 스캔 쌍과 STA 자기 IP를 뽑는다.

    스캔 페어링은 **정방향 단일 슬롯**이다: START를 만나면 슬롯에 넣고, COMPLETED를
    만나면 슬롯과 짝짓고 비운다. 슬롯이 비어 있는데 COMPLETED가 오면 **고아**로
    따로 센다(연결 복구 중 드라이버가 START 1회에 COMPLETED를 2번 올린다 —
    실측 호기당 3~4건).

    역방향("COMPLETED 직전 가장 가까운 START")은 절대 쓰면 안 된다. 고아가 있으면
    4.6초짜리 가짜 스캔이 만들어져 max/p99가 통째로 오염된다(1호기 실측).
    """
    lines = parse_lines(path)
    pairs: List[ScanPair] = []
    orphan_done = 0
    pending: Optional[LogLine] = None
    ips: Dict[str, int] = {}

    for ln in lines:
        if _KERN_SCAN_START.search(ln.msg):
            pending = ln
            continue
        dm = _KERN_SCAN_DONE.search(ln.msg)
        if dm:
            if pending is None:
                orphan_done += 1        # 복구 경로의 중복 COMPLETED
                continue
            pairs.append(ScanPair(
                start_epoch=pending.epoch, done_epoch=ln.epoch,
                ap_count=int(dm.group("count")),
                start_mono=pending.mono, done_mono=ln.mono,
            ))
            pending = None
            continue
        im = _KERN_IP.search(ln.msg)
        if im:
            ip = im.group("ip")
            # 0.0.0.0은 로밍 시작 시 바인딩 해제 표시라 STA 식별에 쓸 수 없다.
            if ip != "0.0.0.0":
                ips[ip] = ips.get(ip, 0) + 1

    return {
        "scans": pairs,
        "orphan_scan_completed": orphan_done,
        "unpaired_scan_start": 1 if pending is not None else 0,
        "ip_counts": ips,
        "sta_ip": max(ips, key=lambda k: ips[k]) if ips else "",
    }


@dataclass
class RoamDecision:
    """logger.log의 로밍 판단 1건 — '왜 로밍했는가'."""
    epoch: float
    from_bssid: str
    to_bssid: str
    rssi: Optional[int] = None
    score: Optional[float] = None
    reason: str = ""
    trigger_rssi: Optional[int] = None    #: roaming condition의 현재 RSSI
    trigger_th: Optional[int] = None      #: 임계값
    trend: str = ""


def parse_logger_log(path: str) -> List[RoamDecision]:
    """logger.log에서 로밍 판단 근거를 뽑는다.

    `Roaming: A → B` 실행 줄을 기준으로, 그 **직전**의 `Roam candidate`(선택 후보와
    점수·사유)와 `roaming condition`(트리거 임계 판단)을 묶는다. 순서는 실측상
    condition → candidate → Roaming 이지만, 누락 가능성을 고려해 직전 값이 있으면
    붙이고 없으면 비워 둔다(지어내지 않는다).

    **중복 제거**: 같은 로밍이 `wifi_roam.py`의 두 지점에서 각각 로그를 남긴다
    (`:2401` 사유·점수 포함, `:1777` 간략). 실측 612줄 = 로밍 306건 × 2라
    그대로 세면 정확히 2배가 된다. 같은 (from, to)가 짧은 시간 안에 다시 나오면
    같은 로밍으로 보고 첫 줄만 취한다(첫 줄이 사유·점수를 갖고 있다).
    """
    lines = parse_lines(path)
    out: List[RoamDecision] = []
    last_cond: Optional[re.Match] = None
    last_cand: Optional[re.Match] = None

    for ln in lines:
        cm = _LOG_CONDITION.search(ln.msg)
        if cm:
            last_cond = cm
            continue
        km = _LOG_CANDIDATE.search(ln.msg)
        if km:
            last_cand = km
            continue
        if _LOG_SKIP.search(ln.msg):
            # 로밍을 하지 않기로 한 줄("Roam skipped" / "No suitable roam candidate").
            # 보류 중인 조건·후보는 **이 판단에서 소진됐다** — 남겨두면 다음 실제
            # 로밍에 남의 근거가 붙는다(실측 로그에서 호기당 스킵 6/18/4건,
            # 그 때문에 낡은 근거가 붙을 수 있는 로밍이 3/9/2건이었다).
            # 앵커를 소비 후 폐기하는 로밍 짝짓기와 같은 규칙이다.
            last_cond = None
            last_cand = None
            continue
        rm = _LOG_ROAMING.search(ln.msg)
        if rm:
            frm, to = rm.group("from").lower(), rm.group("to").lower()
            if out and out[-1].from_bssid == frm and out[-1].to_bssid == to \
                    and ln.epoch - out[-1].epoch <= _SAME_ROAM_LOG_SEC:
                continue        # 같은 로밍의 두 번째 로그 줄 — 첫 줄만 취한다
            d = RoamDecision(
                epoch=ln.epoch,
                from_bssid=frm,
                to_bssid=to,
            )
            if last_cand is not None:
                d.rssi = int(last_cand.group("rssi"))
                d.reason = (last_cand.group("reason") or "").strip()
                try:
                    d.score = float(last_cand.group("score"))
                except (TypeError, ValueError):
                    d.score = None
            if last_cond is not None:
                d.trigger_rssi = int(last_cond.group("rssi"))
                d.trigger_th = int(last_cond.group("th"))
                d.trend = last_cond.group("trend")
            out.append(d)
            # 후보·조건 모두 **소비 즉시** 비운다. 조건 줄을 남겨두면 다음 로밍에
            # `condition:`이 없을 때(파서가 명시적으로 허용하는 경우) 이전 로밍의
            # trigger_rssi/trigger_th/trend가 그대로 붙어, 화면과 sta_log JSON에
            # **없는 근거를 지어내 보여준다**. 앵커를 소비 후 폐기하는 로밍
            # 짝짓기(roaming.pair_roaming_sequences 규칙 3)와 같은 이유다.
            last_cand = None
            last_cond = None
    return out


#: 한 STA(호기)의 로그 세트에서 읽어야 할 파일명.
STATION_LOG_FILES = ("wpa.log", "kern.log", "logger.log")


@dataclass
class StationLog:
    """STA 1대의 로그 세트 파싱 결과."""
    name: str                                   #: 표시용 이름(폴더명 등)
    sta_ip: str = ""                            #: pcap STA 매칭 키
    roams: List[RoamEpisode] = field(default_factory=list)
    scans: List[ScanPair] = field(default_factory=list)
    decisions: List[RoamDecision] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    orphan_scan_completed: int = 0


def parse_station_logs(files: Dict[str, str], name: str = "") -> StationLog:
    """호기 하나의 로그 세트를 파싱한다.

    Args:
        files: {"wpa.log": 경로, "kern.log": 경로, "logger.log": 경로}.
            일부만 있어도 된다 — 없는 건 건너뛰고 경고를 남긴다.
        name: 표시용 이름.
    """
    out = StationLog(name=name)
    if files.get("wpa.log"):
        out.roams = parse_wpa_log(files["wpa.log"])
    else:
        out.warnings.append("wpa.log 없음 — 로밍 전체 소요를 계산할 수 없다")
    if files.get("kern.log"):
        k = parse_kern_log(files["kern.log"])
        out.scans = k["scans"]
        out.sta_ip = k["sta_ip"]
        out.orphan_scan_completed = k["orphan_scan_completed"]
        if not out.sta_ip:
            out.warnings.append(
                "kern.log에서 STA IP를 찾지 못함 — pcap STA와 자동 매칭 불가"
            )
        elif len(k["ip_counts"]) > 1:
            out.warnings.append(
                f"kern.log에 STA IP가 여러 개다({', '.join(sorted(k['ip_counts']))}) — "
                f"DHCP 재할당 가능성. 최빈값 {out.sta_ip}로 매칭한다"
            )
    else:
        out.warnings.append("kern.log 없음 — 스캔 시간·STA 자동 매칭 불가")
    if files.get("logger.log"):
        out.decisions = parse_logger_log(files["logger.log"])
    else:
        out.warnings.append("logger.log 없음 — 로밍 판단 근거를 붙일 수 없다")
    return out


def collect_station_files(directory: str) -> Dict[str, str]:
    """디렉터리에서 STATION_LOG_FILES를 찾아 {파일명: 경로}로. 없는 건 생략."""
    base = Path(directory)
    return {
        n: str(base / n) for n in STATION_LOG_FILES if (base / n).is_file()
    }
