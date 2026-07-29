"""NTP 프레임 기반 캡처↔로그 시각 오프셋 산출 및 로그 타임스탬프 일괄 보정.

2단계로 나뉜다:
  1) `measure_offset()` — sys.log 의 동기화 이벤트와 pcap 의 NTP 응답 프레임을
     `ntp.org`(origin timestamp)로 짝지어, 캡처 시계가 NTP 서버 대비 얼마나
     어긋났는지 산출한다.
  2) `shift_log_file()` — 산출된 오프셋을 로그 파일의 타임스탬프에 일괄 적용해
     새 파일로 쓴다.

오프셋 계산에 `ntp.org` 가 아니라 `ntp.xmt`(서버 송신시각)를 쓰는 이유:
`ntp.org` 는 장치가 요청을 보낸 시각이라 무선구간 재전송·로밍 지연이 그대로
섞여 산포가 수백 ms 로 벌어진다. 반면 NTP 응답은 유선 서버에서 캡처지점까지
sub-ms 라 `arrival - ntp.xmt` 는 사실상 순수 시계차다. 실측에서 IQR 이
407 ms → 3.8 ms 로 100배 좁아졌다. `ntp.org` 는 sys.log 이벤트와 프레임을
짝짓는 **식별 키**로만 쓴다.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from statistics import median

# tshark 가 NTP 타임스탬프를 렌더링하는 형식: "Jul 21, 2026 05:57:35.004315599 UTC"
_NTP_TS_RE = re.compile(r"^(?P<body>[A-Z][a-z]{2} +\d+, +\d{4} +\d{2}:\d{2}:\d{2})\.(?P<frac>\d+)")

#: 월 약어 → 숫자. `%b` 가 LC_TIME 로케일을 타는 것을 피하려고 직접 매핑한다.
_MONTHS: dict[str, str] = {
    m: f"{i:02d}"
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

# 로그 타임스탬프 패턴 — 모두 줄 시작에 앵커한다.
# 본문 안에 박힌 날짜(예: AP 로그의 "NTP: Setting clock (2015-01-01 00:00:07)")를
# 실수로 이동시키지 않기 위해 반드시 앵커가 필요하다.
_TS_BODY = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?"
DEFAULT_LOG_PATTERNS: tuple[str, ...] = (
    rf"^(?P<ts>{_TS_BODY})",  # cpu/kern/logger/summary/sys/wpa.log, DFK AP logfile
    rf"^\[(?P<ts>{_TS_BODY})\]",  # ap/freq/stat.log
    rf"^===== (?P<ts>{_TS_BODY}) =====",  # snap.log
)

DEFAULT_SYNC_PATTERN = r"Contacted time server"
#: 장치 시계가 NTP 서버보다 이만큼(초) 이상 뒤처진 것이 증명되면 경고한다.
#: 실측 잡음(로깅지터)이 수 ms 수준이라 50ms 면 충분히 여유가 있다.
_DEVICE_BEHIND_LIMIT = 0.05
DEFAULT_LOG_GLOBS: tuple[str, ...] = ("*.log", "*.txt")
PCAP_SUFFIXES: tuple[str, ...] = (".pcap", ".pcapng", ".cap")

# 설정 JSON — 두 CLI 가 공유한다.
CONFIG_FILENAME = "timesync.json"
CONFIG_SECTION = "timesync"

#: 설정 파일과 CLI 옵션이 공유하는 키와 내장 기본값.
#: None 은 "지정 안 됨"이며 각 CLI 가 상황에 맞게 처리한다.
DEFAULT_OPTIONS: dict = {
    "syslog": None,  # sys.log 경로 (미지정 시 자동 탐색)
    "pcap": None,  # 분석할 pcap 목록 (미지정 시 자동 탐색)
    "ssid": None,  # WPA 복호화 SSID
    "psk": None,  # WPA 복호화 passphrase
    "tshark": "tshark",  # tshark 실행 경로
    "editcap": "editcap",  # editcap 실행 경로 (pcap 시프트용)
    "pcap_out": None,  # pcap 시프트 출력 디렉터리
    "tz": None,  # 로그 타임스탬프의 타임존 (IANA 이름 또는 "+09:00"). None 이면 시스템 로컬
    "tolerance": 1.0,  # sys.log ↔ ntp.org 매칭 허용오차(초)
    "sync_pattern": DEFAULT_SYNC_PATTERN,
    "offset_out": None,  # 1단계 결과 JSON 경로
    "apply_out": None,  # 2단계 출력 디렉터리
    "source": None,  # 2단계에서 쓸 pcap 이름(부분일치)
    "offset": None,  # 2단계 오프셋 직접 지정(초)
    "glob": list(DEFAULT_LOG_GLOBS),  # 2단계 대상 파일 glob
    "pattern": [],  # 2단계 추가 타임스탬프 정규식
}

#: 값을 여러 개 받는 옵션. 설정 JSON 에 문자열 하나만 와도 리스트로 감싼다.
#: 기본값이 list 인지로 판별하면 `pcap`(기본값 None)이 빠진다 — 명시적으로 적는다.
LIST_OPTION_KEYS: frozenset[str] = frozenset({"pcap", "glob", "pattern"})


@dataclass
class NtpResponse:
    """pcap 에서 뽑은 NTP 서버 응답(mode 4) 한 건."""

    frame_no: int
    arrival: float  # 캡처 장비 시계 기준 도착 시각 (epoch)
    org: float  # origin timestamp — 장치가 요청을 보낸 시각 (장치 시계)
    xmt: float  # transmit timestamp — 서버가 응답을 보낸 시각 (서버 시계)
    src: str = ""  # NTP 서버 IP
    dst: str = ""  # 이 응답을 받는 장비 IP — 어느 장비의 교환인지 가른다


@dataclass
class SyncEvent:
    """sys.log 에 기록된 시각 동기화 이벤트 한 건."""

    line_no: int
    ts: float  # 장치 시계 기준 epoch
    text: str


@dataclass
class Match:
    """sys.log 이벤트 ↔ NTP 응답 프레임 짝."""

    event: SyncEvent
    response: NtpResponse
    residual: float  # |event.ts - response.org| — 짝짓기 근거

    @property
    def capture_minus_ntp(self) -> float:
        """캡처 시계 − NTP 서버 시계. 양수면 캡처 장비가 앞선다."""
        return self.response.arrival - self.response.xmt

    @property
    def device_minus_ntp(self) -> float:
        """장치 로그 시계 − NTP 서버 시계의 **상한**.

        sys.log 기록 시각은 응답 수신(T4) 이후이므로 편도지연 + 로깅지연이
        더해져 있다. 실제 시계차는 이 값보다 작다.
        """
        return self.event.ts - self.response.xmt


@dataclass
class Stats:
    """분포 요약."""

    n: int
    median: float
    q1: float
    q3: float
    min: float
    max: float

    @property
    def iqr(self) -> float:
        return self.q3 - self.q1

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "median": self.median,
            "q1": self.q1,
            "q3": self.q3,
            "min": self.min,
            "max": self.max,
            "iqr": self.iqr,
        }


@dataclass
class OffsetResult:
    """pcap 한 개에 대한 오프셋 측정 결과."""

    pcap: str
    ntp_responses: int
    matched: int
    capture_minus_ntp: Stats | None
    device_minus_ntp_upper: Stats | None
    drift_ppm: float | None
    residual: Stats | None
    samples: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: 정보성 메모. 어떤 단계도 막지 않는다.
    notes: list[str] = field(default_factory=list)
    #: **로그** 보정에만 영향을 주는 경고. pcap 보정은 막지 않는다 —
    #: pcap 을 NTP 서버 시각에 맞추는 데 장치 시계는 무관하기 때문이다.
    log_warnings: list[str] = field(default_factory=list)
    device_ip: str = ""  # 이 로그의 장비 IP (NTP 교환 상대) — 자동 판별
    syslog: str = ""  # 이 결과를 만든 sys.log (여러 장비 중 어느 것을 썼는지)
    #: "syslog-matched" — sys.log 이벤트와 짝지은 프레임만 사용 (장치 시계 검증 가능)
    #: "ntp-only"       — 대응하는 sys.log 가 없어 NTP 프레임 전체로 산출
    method: str = ""

    @property
    def log_shift_seconds(self) -> float | None:
        """로그를 이 캡처의 타임라인으로 옮길 때 더할 값(초).

        장치가 NTP 규율 상태라는 전제 하에 캡처↔NTP 서버 차이를 그대로 쓴다.
        전제가 깨지면 `warnings` 에 경고가 담긴다.
        """
        if self.capture_minus_ntp is None:
            return None
        return self.capture_minus_ntp.median

    def as_dict(self) -> dict:
        return {
            "pcap": self.pcap,
            "syslog": self.syslog,
            "device_ip": self.device_ip,
            "method": self.method,
            "ntp_responses": self.ntp_responses,
            "matched": self.matched,
            "capture_minus_ntp": self.capture_minus_ntp.as_dict() if self.capture_minus_ntp else None,
            "device_minus_ntp_upper": (
                self.device_minus_ntp_upper.as_dict() if self.device_minus_ntp_upper else None
            ),
            "match_residual": self.residual.as_dict() if self.residual else None,
            "drift_ppm": self.drift_ppm,
            "log_shift_seconds": self.log_shift_seconds,
            "samples": self.samples,
            "warnings": self.warnings,
            "log_warnings": self.log_warnings,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------
# 파싱
# --------------------------------------------------------------------------


def parse_ntp_timestamp(raw: str) -> float | None:
    """tshark 가 출력한 NTP 타임스탬프 문자열을 epoch(초)로 변환한다.

    나노초 9자리를 그대로 `%f` 에 넘기면 실패하므로 마이크로초로 줄인다.
    미설정 필드('NULL', 빈 문자열, 1900 epoch)는 None 을 돌려준다.
    """
    if not raw or raw == "NULL":
        return None
    body = raw.replace(" UTC", "").strip()
    m = _NTP_TS_RE.match(body)
    if m:
        base, frac = m.group("body"), m.group("frac")[:6].ljust(6, "0")
        body = f"{base}.{frac}"
    else:
        body = f"{body}.000000"
    # `%b` 는 LC_TIME 로케일을 탄다. tshark 는 로케일과 무관하게 영어 월 이름을
    # 내보내므로, 분석 서버 로케일이 비영어면 파싱이 통째로 실패하고 NTP 0건이 된다.
    # 월 이름을 직접 숫자로 바꿔 로케일 의존을 끊는다.
    mon = _MONTHS.get(body[:3].title())
    if mon is None:
        return None
    try:
        dt = datetime.strptime(f"{mon}{body[3:]}", "%m %d, %Y %H:%M:%S.%f")
    except ValueError:
        return None
    epoch = dt.replace(tzinfo=timezone.utc).timestamp()
    # NTP 미설정 필드는 1900-01-01(=epoch -2208988800) 근처로 렌더링된다.
    return epoch if epoch > 0 else None


def encode_wpa_field(value: str) -> str:
    """tshark `uat:80211_keys` 의 `wpa-pwd` 레코드에 넣을 수 있게 가공한다.

    이 필드는 tshark 가 **퍼센트 디코딩**한 뒤 `passphrase:ssid` 로 쪼갠다. 실측한
    tshark 동작(4.x):

    - `:` 를 그냥 넣으면 `Only one ':' is allowed …` 로 거부된다 → `%3a` 로 인코딩
    - `%` 를 그냥 넣으면 디코딩되어 **조용히 다른 키**가 된다 → `%25` 로 인코딩
      (tshark 도 `use "%25" for a literal "%"` 라고 안내한다)
    - `"` 는 UAT 파서가 레코드 경계로 읽어 깨진다. `""` 이중화도 실패해서
      빠져나갈 방법이 없다 → ValueError 로 거부한다
    - `\\` 와 `,` 는 그대로 통과한다

    순서가 중요하다 — `%` 를 먼저 바꿔야 `%3a` 의 `%` 가 다시 인코딩되지 않는다.
    """
    if '"' in value:
        raise ValueError(
            'SSID/passphrase 에 " 가 있으면 tshark 에 넘길 수 없다 '
            "(UAT 파서가 레코드 경계로 읽고, 이중화 이스케이프도 통하지 않는다)"
        )
    return value.replace("%", "%25").replace(":", "%3a")


def build_ntp_tshark_cmd(
    pcap: str | Path,
    *,
    tshark_path: str = "tshark",
    ssid: str | None = None,
    passphrase: str | None = None,
    mode: int = 4,
) -> list[str]:
    """NTP 프레임 추출용 tshark 명령을 만든다.

    ssid/passphrase 가 주어지면 WPA 복호화를 켠다. 암호화된 802.11 모니터
    캡처는 복호화 없이는 NTP 가 한 건도 보이지 않는다.
    """
    cmd = [
        str(tshark_path),
        "-r",
        str(pcap),
        "-Y",
        f"ntp.flags.mode=={mode}",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "ntp.org",
        "-e",
        "ntp.xmt",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
    ]
    if ssid and passphrase:
        cmd += [
            "-o",
            "wlan.enable_decryption:TRUE",
            "-o",
            f'uat:80211_keys:"wpa-pwd","{encode_wpa_field(passphrase)}:{encode_wpa_field(ssid)}"',
        ]
    return cmd


def extract_ntp_responses(
    pcap: str | Path,
    *,
    tshark_path: str = "tshark",
    ssid: str | None = None,
    passphrase: str | None = None,
    timeout: int | None = None,
) -> tuple[list[NtpResponse], list[str]]:
    """pcap 에서 NTP 서버 응답(mode 4) 프레임을 뽑는다.

    Returns:
        (프레임 목록, 경고 목록)

    tshark 가 0 이 아닌 코드로 끝났는데 stdout 이 일부 있으면(잘린 pcap 등)
    그 부분 결과를 쓰되 **반드시 경고를 남긴다**. 조용히 쓰면 캡처가 잘린
    구간을 못 본 채 오프셋을 확정하게 된다.
    """
    cmd = build_ntp_tshark_cmd(pcap, tshark_path=tshark_path, ssid=ssid, passphrase=passphrase)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"tshark 실패 ({pcap}): {proc.stderr.strip()[:300]}")
    warnings: list[str] = []
    if proc.returncode != 0:
        # 잘린 pcap 이다. 읽힌 프레임 자체는 정상이고 editcap 도 코드 0 으로 복구하므로
        # 오프셋을 무효화하지는 않는다 — 다만 출력이 원본보다 짧다는 사실은 알려야 한다.
        warnings.append(
            f"tshark 가 코드 {proc.returncode} 로 끝나 읽힌 부분만 사용한다 "
            f"(pcap 끝이 잘렸다): {proc.stderr.strip()[:200]}"
        )
    return parse_ntp_tsv(proc.stdout), warnings


def parse_ntp_tsv(text: str) -> list[NtpResponse]:
    """`build_ntp_tshark_cmd` 출력 TSV 를 파싱한다."""
    out: list[NtpResponse] = []
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) < 4 or not cols[0].strip() or not cols[1].strip():
            continue
        org = parse_ntp_timestamp(cols[2])
        xmt = parse_ntp_timestamp(cols[3])
        if org is None or xmt is None:
            continue
        try:
            frame_no, arrival = int(cols[0]), float(cols[1])
        except ValueError:
            continue
        out.append(
            NtpResponse(
                frame_no=frame_no,
                arrival=arrival,
                org=org,
                xmt=xmt,
                src=cols[4] if len(cols) > 4 else "",
                dst=cols[5] if len(cols) > 5 else "",
            )
        )
    out.sort(key=lambda r: r.arrival)
    return out


def resolve_tz(name: str | None) -> tzinfo | None:
    """타임존 이름을 tzinfo 로 바꾼다. None/빈값이면 None(=시스템 로컬).

    IANA 이름("Asia/Seoul")과 고정 오프셋("+09:00", "-0530") 을 모두 받는다.
    로그 파일은 오프셋 표기가 없는 로컬 시각 문자열이라, 캡처를 만든 장비와
    분석하는 장비의 TZ 가 다르면 이 값을 반드시 지정해야 한다.
    """
    if not name:
        return None
    text = str(name).strip()
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
        return timezone(sign * delta)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(text)
    except Exception as exc:  # ZoneInfoNotFoundError 등
        raise ValueError(
            f"타임존을 해석할 수 없다: {name!r} "
            '(IANA 이름 예 "Asia/Seoul", 고정 오프셋 예 "+09:00")'
        ) from exc


def parse_log_timestamp(raw: str, tz: tzinfo | None = None) -> float:
    """로그 타임스탬프 문자열을 epoch(초)로 변환한다.

    tz 가 None 이면 시스템 로컬 타임존으로 해석한다.
    """
    body, _, frac = raw.partition(".")
    dt = datetime.strptime(body, "%Y-%m-%d %H:%M:%S")
    if frac:
        dt = dt.replace(microsecond=int(frac[:6].ljust(6, "0")))
    dt = dt.replace(tzinfo=tz) if tz is not None else dt.astimezone()
    return dt.timestamp()


def parse_sync_events(
    syslog: str | Path,
    *,
    pattern: str = DEFAULT_SYNC_PATTERN,
    tz: tzinfo | None = None,
) -> list[SyncEvent]:
    """sys.log 에서 시각 동기화 이벤트를 뽑는다.

    기본 패턴은 systemd-timesyncd 의 "Contacted time server ..." 라인이다.
    """
    needle = re.compile(pattern)
    head = re.compile(rf"^(?P<ts>{_TS_BODY})")
    events: list[SyncEvent] = []
    with open(syslog, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            if not needle.search(line):
                continue
            m = head.match(line)
            if not m:
                continue
            try:
                ts_val = parse_log_timestamp(m.group("ts"), tz)
            except (ValueError, OverflowError, OSError):
                # 깨진 날짜 한 줄 때문에 1단계 전체가 죽으면 안 된다.
                continue
            events.append(SyncEvent(line_no=i, ts=ts_val, text=line.rstrip("\n")))
    return events


# --------------------------------------------------------------------------
# 매칭 · 통계
# --------------------------------------------------------------------------


def match_events(
    events: list[SyncEvent],
    responses: list[NtpResponse],
    *,
    tolerance: float = 1.0,
    dst: str | None = None,
) -> list[Match]:
    """sys.log 이벤트를 `ntp.org` 가 가장 가까운 NTP 응답에 짝짓는다.

    sys.log 기록은 응답 수신 직후이고 `ntp.org` 는 요청 송신 시각이므로,
    둘의 차이는 왕복시간 + 로깅지연(실측 중앙값 0.43 s)이다. tolerance 는
    이보다 넉넉해야 한다.

    한 응답이 여러 이벤트에 중복 배정되지 않도록 1:1 로 소비한다.
    """
    if dst is not None:
        responses = [r for r in responses if r.dst == dst]
    by_org = sorted(responses, key=lambda r: r.org)
    used: set[int] = set()
    matches: list[Match] = []
    for ev in events:
        best: Match | None = None
        best_idx = -1
        for idx, resp in enumerate(by_org):
            if idx in used:
                continue
            d = abs(resp.org - ev.ts)
            if d > tolerance:
                continue
            if best is None or d < best.residual:
                best = Match(event=ev, response=resp, residual=d)
                best_idx = idx
        if best is not None:
            used.add(best_idx)
            matches.append(best)
    matches.sort(key=lambda m: m.response.arrival)
    return matches


def _fmt_epoch(epoch: float, tz: tzinfo | None = None) -> str:
    """샘플 출력용 시각 문자열 (ms 까지)."""
    dt = datetime.fromtimestamp(epoch, tz) if tz is not None else datetime.fromtimestamp(epoch)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def summarize(values: list[float]) -> Stats | None:
    """중앙값·사분위수 요약. 표본이 없으면 None."""
    if not values:
        return None
    xs = sorted(values)
    n = len(xs)

    def q(p: float) -> float:
        if n == 1:
            return xs[0]
        pos = p * (n - 1)
        lo = int(pos)
        hi = min(lo + 1, n - 1)
        return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)

    return Stats(n=n, median=median(xs), q1=q(0.25), q3=q(0.75), min=xs[0], max=xs[-1])


def linear_drift_ppm(points: list[tuple[float, float]]) -> float | None:
    """(시각, 오프셋) 점들의 선형 기울기를 ppm 으로 돌려준다.

    양수면 시간이 갈수록 캡처 시계가 기준 대비 빨라진다는 뜻이다.
    """
    if len(points) < 3:
        return None
    t0 = points[0][0]
    xs = [p[0] - t0 for p in points]
    ys = [p[1] for p in points]
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    return slope * 1e6


def measure_offset(
    pcap: str | Path,
    events: list[SyncEvent],
    *,
    tshark_path: str = "tshark",
    ssid: str | None = None,
    passphrase: str | None = None,
    tolerance: float = 1.0,
    max_samples: int = 5,
    device_offset_warn: float = 1.0,
    tz: tzinfo | None = None,
) -> OffsetResult:
    """pcap 한 개에 대해 캡처 시계 오프셋을 측정한다."""
    pcap = Path(pcap)
    responses, tshark_warnings = extract_ntp_responses(
        pcap, tshark_path=tshark_path, ssid=ssid, passphrase=passphrase
    )
    return analyze_offset(
        pcap,
        responses,
        tshark_warnings,
        events,
        tolerance=tolerance,
        max_samples=max_samples,
        device_offset_warn=device_offset_warn,
        tz=tz,
    )


def measure_offset_best(
    pcap: str | Path,
    event_sets: list[tuple[str, list[SyncEvent]]],
    *,
    tshark_path: str = "tshark",
    ssid: str | None = None,
    passphrase: str | None = None,
    **kwargs,
) -> OffsetResult:
    """여러 sys.log 후보 중 가장 잘 맞는 것으로 오프셋을 측정한다.

    한 데이터셋에 여러 장비의 로그가 있고 일부만 캡처 구간과 겹치는 경우가 있다.
    tshark 추출은 한 번만 하고, 매칭만 후보별로 다시 돌려 가장 표본이 많은 것을
    고른다. 오프셋 자체는 `arrival - ntp.xmt` 라는 프레임 단위 값이라 어느 로그로
    골랐는지에 좌우되지 않는다 — 로그는 '어느 프레임을 쓸지'만 정한다.
    """
    pcap = Path(pcap)
    responses, tshark_warnings = extract_ntp_responses(
        pcap, tshark_path=tshark_path, ssid=ssid, passphrase=passphrase
    )
    if not event_sets:
        return analyze_offset(pcap, responses, tshark_warnings, [], **kwargs)

    best: OffsetResult | None = None
    for label, events in event_sets:
        # 후보를 재는 동안에는 폴백을 끈다 — 켜두면 첫 후보가 곧바로 ntp-only 로
        # 성공해버려 정작 맞는 로그를 못 찾는다.
        res = analyze_offset(
            pcap, responses, tshark_warnings, events, allow_ntp_only=False, **kwargs
        )
        res.syslog = label
        if best is None or res.matched > best.matched:
            best = res
        if best.matched == len(responses):
            break  # 더 나아질 수 없다
    if best is None:  # event_sets 가 비어있지 않으면 도달 불가 — -O 에서도 살아남게 raise
        raise RuntimeError("내부 오류: 후보 로그가 하나도 평가되지 않았다")
    if best.matched == 0:
        # 어느 로그와도 안 맞았다 — 대응 구간이 없는 캡처다. NTP 프레임만으로 낸다.
        best = analyze_offset(pcap, responses, tshark_warnings, [], **kwargs)
    # 어느 후보를 골랐는지는 `syslog` 필드에 담긴다. warnings 에 넣으면 안 된다 —
    # 그 목록은 "이 오프셋을 그대로 쓰지 말라"는 뜻이라 2단계가 적용을 거부한다.
    return best


def analyze_offset(
    pcap: str | Path,
    responses: list[NtpResponse],
    tshark_warnings: list[str],
    events: list[SyncEvent],
    *,
    tolerance: float = 1.0,
    max_samples: int = 5,
    device_offset_warn: float = 1.0,
    tz: tzinfo | None = None,
    allow_ntp_only: bool = True,
) -> OffsetResult:
    """이미 뽑아둔 NTP 프레임과 동기화 이벤트로 오프셋을 산출한다.

    tshark 재실행 없이 여러 sys.log 후보를 시도할 수 있게 추출과 분리했다.

    allow_ntp_only 가 True 면, sys.log 매칭이 하나도 안 될 때 NTP 프레임 전체로
    오프셋을 낸다(method="ntp-only"). 한 데이터셋에 여러 세션의 캡처가 섞여 있어
    일부 pcap 에는 대응 로그가 없는 경우를 위한 것이다.
    """
    pcap = Path(pcap)
    result = OffsetResult(
        pcap=str(pcap),
        ntp_responses=len(responses),
        matched=0,
        capture_minus_ntp=None,
        device_minus_ntp_upper=None,
        drift_ppm=None,
        residual=None,
    )
    result.notes.extend(tshark_warnings)
    if not responses:
        result.warnings.append(
            "NTP mode 4 프레임 0건 — 암호화된 802.11 캡처라면 --ssid/--psk 로 복호화가 필요하다."
        )
        return result

    # 한 캡처에는 여러 장비의 NTP 교환이 섞여 있다(.21/.22/.23 …). IP 를 안 가리면
    # 한 로그의 이벤트가 남의 장비 프레임에 붙어 device_minus_ntp — 즉 "로그를 옮길지
    # pcap 을 옮길지" 를 가르는 장치 시계 검증 — 이 오염된다. 실측에서 53건 중 4건이
    # 오매칭됐고 그 값이 -0.29~-1.00s 로 정상범위(+0.001~+0.075) 를 벗어났다.
    # 어느 IP 가 이 로그의 장비인지는 매칭 표본수로 자동 판별한다.
    candidates = sorted({r.dst for r in responses if r.dst})
    matches: list[Match] = []
    device_ip = ""
    if candidates:
        for cand in candidates:
            m = match_events(events, responses, tolerance=tolerance, dst=cand)
            if not m:
                continue
            if len(m) > len(matches) or (
                len(m) == len(matches)
                and median([x.residual for x in m]) < median([x.residual for x in matches])
            ):
                matches, device_ip = m, cand
    else:
        # ip.dst 를 못 뽑은 캡처 — 예전처럼 전체에서 매칭한다.
        matches = match_events(events, responses, tolerance=tolerance)
    result.device_ip = device_ip
    if not matches:
        if not allow_ntp_only:
            result.warnings.append(
                f"sys.log 이벤트({len(events)}건)와 짝지어진 프레임 없음 "
                f"— tolerance({tolerance}s)를 늘리거나 sys.log 가 이 캡처와 같은 구간인지 확인하라."
            )
            return result
        # 한 폴더에 여러 세션이 섞여 있으면 일부 pcap 은 대응하는 sys.log 가 없다.
        # 그래도 오프셋은 낼 수 있다: arrival - ntp.xmt 는 "캡처지점 - NTP서버" 라는
        # 프레임 단위 물리량이라 어느 클라이언트 앞으로 가는 응답인지와 무관하다.
        # (실측 대조: 같은 캡처에서 sys.log 매칭 -24.309579s vs 전체 -24.309565s,
        #  차이 14us) 다만 장치 시계 검증은 할 수 없다.
        result.method = "ntp-only"
        result.syslog = ""
        deltas = [(r.arrival, r.arrival - r.xmt) for r in responses]
        result.capture_minus_ntp = summarize([d for _, d in deltas])
        result.drift_ppm = linear_drift_ppm(deltas)
        # 정보성이다 — pcap 보정에는 장치 시계가 무관하므로 막지 않는다.
        # 로그 보정(timesync-apply.py)은 method=="ntp-only" 를 별도로 막는다.
        result.notes.append(
            f"대응하는 sys.log 구간이 없어 NTP 프레임 {len(responses)}건 전체로 산출했다 "
            "— 오프셋은 유효하지만 장치 시계가 NTP 규율 상태인지는 확인하지 못했다."
        )
        step = max(1, len(responses) // max_samples)
        for r in responses[::step][:max_samples]:
            result.samples.append(
                {
                    "frame": r.frame_no,
                    "arrival": _fmt_epoch(r.arrival, tz),
                    "ntp_xmt": _fmt_epoch(r.xmt, tz),
                    "capture_minus_ntp": round(r.arrival - r.xmt, 6),
                }
            )
        return result
    result.method = "syslog-matched"

    result.matched = len(matches)
    result.capture_minus_ntp = summarize([m.capture_minus_ntp for m in matches])
    result.device_minus_ntp_upper = summarize([m.device_minus_ntp for m in matches])
    result.residual = summarize([m.residual for m in matches])
    result.drift_ppm = linear_drift_ppm([(m.response.arrival, m.capture_minus_ntp) for m in matches])

    # device_minus_ntp = (장치시계 − 서버시계) + 편도지연 + 로깅지연.
    # 뒤의 두 항은 항상 0 이상이므로 (장치시계 − 서버시계) <= 관측값 이 성립한다.
    # 따라서 관측값이 음수이면 장치가 그만큼 **확실히** 뒤처져 있다는 하드 바운드다.
    # 반대로 양수는 지연에 묻힐 수 있어 느슨한 임계값으로만 본다.
    dev = result.device_minus_ntp_upper
    if dev is not None:
        if dev.median < -_DEVICE_BEHIND_LIMIT:
            result.log_warnings.append(
                f"장치 로그 시계가 NTP 서버보다 최소 {-dev.median:.3f}s 뒤처져 있다"
                "(편도지연을 무시한 하한) — 장치가 NTP 규율 상태라는 전제가 깨졌으므로 "
                "log_shift_seconds 를 그대로 쓰면 안 된다."
            )
        elif dev.median > device_offset_warn:
            result.log_warnings.append(
                f"장치 로그 시계가 NTP 서버 대비 {dev.median:+.3f}s 로 벌어져 있다 "
                "(지연 포함 상한) — 장치 시계가 앞서 있거나 응답 지연이 크다. "
                "log_shift_seconds 를 그대로 쓰기 전에 확인하라."
            )
    if result.matched < 3:
        result.warnings.append(f"매칭 표본이 {result.matched}건뿐이라 오프셋 신뢰도가 낮다.")

    step = max(1, len(matches) // max_samples)
    for m in matches[::step][:max_samples]:
        result.samples.append(
            {
                "syslog_line": m.event.line_no,
                "syslog_time": _fmt_epoch(m.event.ts, tz),
                "ntp_org": _fmt_epoch(m.response.org, tz),
                "frame": m.response.frame_no,
                "arrival": _fmt_epoch(m.response.arrival, tz),
                "ntp_xmt": _fmt_epoch(m.response.xmt, tz),
                "capture_minus_ntp": round(m.capture_minus_ntp, 6),
            }
        )
    return result


# --------------------------------------------------------------------------
# 로그 타임스탬프 이동
# --------------------------------------------------------------------------


def _shift_timestamp_text(ts: str, delta: float) -> str:
    """타임스탬프 문자열에 delta(초)를 더하되 소수 자릿수를 보존한다."""
    body, dot, frac = ts.partition(".")
    width = len(frac) if dot else 0
    dt = datetime.strptime(body, "%Y-%m-%d %H:%M:%S")
    if width:
        dt = dt.replace(microsecond=int(frac[:6].ljust(6, "0")))
    dt += timedelta(seconds=delta)

    if width == 0:
        # 소수부가 없는 포맷은 가장 가까운 초로 반올림한다.
        if dt.microsecond >= 500_000:
            dt += timedelta(seconds=1)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    if width <= 6:
        scale = 10**width
        val = round(dt.microsecond * scale / 1_000_000)
        if val >= scale:  # 반올림 올림 발생
            dt += timedelta(seconds=1)
            val = 0
        return dt.strftime("%Y-%m-%d %H:%M:%S") + "." + str(val).zfill(width)
    # 6자리 초과(나노초 등): delta 는 timedelta 해상도라 마이크로초까지만 유효하다.
    # 마이크로초까지만 옮기고 그 아래 자릿수는 원본 그대로 이어붙인다 —
    # 0으로 덮으면 있지도 않은 정밀도를 지어내거나 있던 정밀도를 지운다.
    return dt.strftime("%Y-%m-%d %H:%M:%S") + "." + str(dt.microsecond).zfill(6) + frac[6:]


def shift_line(line: str, delta: float, patterns: list[re.Pattern]) -> tuple[str, bool]:
    """한 줄의 타임스탬프를 이동시킨다. (새 줄, 변경여부)를 돌려준다."""
    for pat in patterns:
        m = pat.match(line)
        if not m:
            continue
        try:
            new_ts = _shift_timestamp_text(m.group("ts"), delta)
        except (ValueError, OverflowError, OSError):
            # 파싱 불가하거나 delta 가 너무 커서 datetime 범위를 벗어난 경우.
            # 예외를 밖으로 던지면 이미 쓴 파일만 남은 반쪽 출력 트리가 된다.
            return line, False
        s, e = m.span("ts")
        return line[:s] + new_ts + line[e:], True
    return line, False


def compile_patterns(patterns: tuple[str, ...] | list[str] = DEFAULT_LOG_PATTERNS) -> list[re.Pattern]:
    """타임스탬프 정규식을 컴파일한다.

    `(?P<ts>...)` 그룹이 없으면 `shift_line` 이 나중에 IndexError 로 죽으면서
    반쯤 쓰인 출력 트리를 남기므로, 여기서 미리 걸러 ValueError 로 알린다.
    """
    compiled: list[re.Pattern] = []
    for p in patterns:
        try:
            rx = re.compile(p)
        except re.error as exc:
            raise ValueError(f"정규식 컴파일 실패: {p!r} ({exc})") from exc
        if "ts" not in rx.groupindex:
            raise ValueError(f"정규식에 (?P<ts>...) 그룹이 없다: {p!r}")
        compiled.append(rx)
    return compiled


def shift_log_file(
    src: str | Path,
    dst: str | Path,
    delta: float,
    *,
    patterns: list[re.Pattern] | None = None,
    dry_run: bool = False,
) -> tuple[int, int]:
    """로그 파일 하나의 타임스탬프를 일괄 이동해 새 파일로 쓴다.

    Returns:
        (전체 줄 수, 이동된 줄 수)

    바이트를 그대로 보존하기 위해 surrogateescape 로 읽고 쓰며,
    개행문자(CRLF/LF)도 원본 그대로 유지한다.

    읽으면서 바로 쓴다 — 로그가 수 GB 여도 메모리에 통째로 올리지 않는다.
    중간에 끊기면 `shift_pcap_file` 과 같이 만들다 만 출력 파일을 지운다.

    `src` 와 `dst` 가 같으면 거부한다. 스트리밍 쓰기라 출력 파일을 여는 순간 원본이
    0바이트로 잘리고, 읽을 것이 없어 조용히 빈 파일만 남는다. 원본 보존이 이 도구의
    제1원칙이라 호출자 실수를 여기서 막는다.
    """
    if Path(src).resolve() == Path(dst).resolve():
        raise ValueError(f"입력과 출력이 같은 파일이다 — 원본이 지워진다: {src}")

    pats = patterns if patterns is not None else compile_patterns()
    total = changed = 0

    if dry_run:
        with open(src, encoding="utf-8", errors="surrogateescape", newline="") as fh:
            for line in fh:
                total += 1
                changed += shift_line(line, delta, pats)[1]
        return total, changed

    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (
            open(src, encoding="utf-8", errors="surrogateescape", newline="") as fin,
            open(dst, "w", encoding="utf-8", errors="surrogateescape", newline="") as fout,
        ):
            for line in fin:
                total += 1
                new_line, did = shift_line(line, delta, pats)
                changed += did
                fout.write(new_line)
    except BaseException:
        # 반쪽 파일이 남으면 다음 실행에서 원본으로 오인될 수 있다.
        dst.unlink(missing_ok=True)
        raise
    return total, changed


# --------------------------------------------------------------------------
# 설정 JSON
# --------------------------------------------------------------------------


def extract_options(doc: dict) -> dict:
    """설정 JSON 문서에서 옵션 딕셔너리를 꺼낸다.

    세 가지 모양을 모두 받아들인다:
      1. 평범한 옵션 딕셔너리          {"ssid": ..., "tolerance": ...}
      2. 1단계가 만든 결과 JSON        {"options": {...}, "sources": [...]}
      3. 큰 설정파일 안의 하위 섹션    {"timesync": {...}}
    2번 덕분에 1단계 출력을 그대로 --config 로 되먹여 옵션을 재사용할 수 있다.

    1번 모양에서는 키를 걸러내지 않고 그대로 돌려준다. 걸러내면 `tolerence`
    같은 오타가 조용히 무시돼 설정이 안 먹는 이유를 알 수 없게 되므로,
    `load_config()` 가 모르는 키를 에러로 잡게 한다.
    """
    if not isinstance(doc, dict):
        raise ValueError("설정 JSON 의 최상위는 객체(dict)여야 한다.")
    for key in ("options", CONFIG_SECTION):
        section = doc.get(key)
        if isinstance(section, dict):
            return dict(section)
    if isinstance(doc.get("sources"), list):
        # options 블록이 없는 구버전 1단계 결과 — 옵션은 없는 것으로 본다.
        return {}
    return dict(doc)


def find_config(search_from: str | Path | None) -> Path | None:
    """설정 파일을 자동 탐색한다.

    탐색 순서: <search_from>/timesync.json → <search_from>/../timesync.json
    → <cwd>/timesync.json. 2단계는 로그 디렉터리(예 `<dataset>/1호기`)를 받으므로
    부모까지 봐야 데이터셋 루트의 설정을 집는다.
    """
    candidates: list[Path] = []
    if search_from is not None:
        base = Path(search_from)
        base = base if base.is_dir() else base.parent
        candidates += [base / CONFIG_FILENAME, base.parent / CONFIG_FILENAME]
    candidates.append(Path.cwd() / CONFIG_FILENAME)
    for c in candidates:
        if c.is_file():
            return c
    return None


def load_config(
    explicit: str | Path | None = None,
    *,
    search_from: str | Path | None = None,
    auto: bool = True,
) -> tuple[dict, Path | None]:
    """설정 JSON 을 읽어 (옵션 딕셔너리, 사용한 경로)를 돌려준다.

    explicit 이 주어지면 그것만 쓰고, 없으면 auto 일 때만 자동 탐색한다.
    설정이 없으면 ({}, None).
    """
    path = Path(explicit) if explicit else (find_config(search_from) if auto else None)
    if path is None:
        return {}, None
    if not path.is_file():
        raise FileNotFoundError(f"설정 파일 없음: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"설정 JSON 파싱 실패 ({path}): {exc}") from exc
    opts = extract_options(doc)
    unknown = sorted(set(opts) - set(DEFAULT_OPTIONS))
    if unknown:
        raise ValueError(
            f"설정 파일에 알 수 없는 키가 있다 ({path}): {', '.join(unknown)}\n"
            f"  사용 가능한 키: {', '.join(sorted(DEFAULT_OPTIONS))}"
        )
    return opts, path


def _coerce(key: str, value):
    """설정 JSON 값의 타입을 옵션 기본값에 맞춰 정규화한다."""
    if value is None:
        return None
    if key in LIST_OPTION_KEYS and isinstance(value, str):
        # 리스트 옵션에 문자열 하나만 준 경우 관용 처리.
        # 기본값이 list 인지로 판별하면 안 된다 — `pcap` 의 기본값은 None 이라
        # 그 방식으로는 안 걸리고, 소비자가 문자열을 글자 단위로 순회한다.
        return [value]
    if key in ("tolerance", "offset"):
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"설정 키 {key!r} 는 숫자여야 한다 (받은 값: {value!r})") from exc
    return value


def merge_options(cli: dict, config: dict) -> dict:
    """CLI 인자 > 설정 파일 > 내장 기본값 순으로 옵션을 합친다.

    CLI 쪽 값이 None 이면 "지정 안 됨"으로 본다. 그래서 각 CLI 의 argparse
    default 는 반드시 None 이어야 한다.
    """
    # 얕은 복사면 리스트 옵션이 모듈 전역 기본값을 그대로 참조해,
    # 호출자가 merged["glob"].append(...) 하면 기본값이 오염된다.
    merged = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULT_OPTIONS.items()}
    for key, value in config.items():
        if key in merged:
            merged[key] = _coerce(key, value)
    for key, value in cli.items():
        if key in merged and value is not None:
            merged[key] = value
    return merged


# --------------------------------------------------------------------------
# 디렉터리 탐색
# --------------------------------------------------------------------------


def find_pcaps(root: str | Path) -> list[Path]:
    """디렉터리 트리에서 pcap/pcapng 파일을 찾는다."""
    root = Path(root)
    if root.is_file():
        return [root]
    out = [p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES]
    return out


def find_syslogs(root: str | Path, name: str = "sys.log") -> list[Path]:
    """디렉터리 트리에서 sys.log 를 **모두** 찾는다.

    한 데이터셋에 1호기/2호기/3호기 처럼 여러 장비의 로그가 들어있고,
    그중 일부만 캡처 구간과 겹치는 경우가 있다. 하나만 골라 쓰면 하필
    안 겹치는 것을 집었을 때 데이터셋 전체를 못 쓰게 된다.
    """
    root = Path(root)
    if root.is_file():
        return [root]
    return sorted(root.rglob(name), key=lambda p: (len(p.parts), str(p)))


def find_syslog(root: str | Path, name: str = "sys.log") -> Path | None:
    """디렉터리 트리에서 sys.log 를 찾는다. 여러 개면 가장 얕은 것을 고른다."""
    cands = find_syslogs(root, name)
    return cands[0] if cands else None


def find_log_files(root: str | Path, globs: tuple[str, ...] = DEFAULT_LOG_GLOBS) -> list[Path]:
    """보정 대상 로그 파일을 찾는다. root 밖으로 나가는 결과는 버린다.

    `rglob("../*.log")` 같은 패턴은 상위 디렉터리를 타고 올라간다. 그대로 두면
    2단계에서 `dst = outdir / src.relative_to(base)` 가 `outdir/../x.log` 로
    풀려 출력 디렉터리 밖의 원본을 덮어쓴다. 그래서 여기서 잘라낸다.
    """
    root = Path(root)
    if root.is_file():
        return [root]
    root_res = root.resolve()
    seen: dict[Path, None] = {}
    for g in globs:
        for p in sorted(root.rglob(g)):
            if not p.is_file():
                continue
            if not p.resolve().is_relative_to(root_res):
                continue
            seen.setdefault(p, None)
    return list(seen)


def pcap_shift_seconds(capture_minus_ntp: float) -> float:
    """캡처 오프셋으로부터 pcap 에 적용할 보정량(초)을 구한다.

    `capture_minus_ntp` 는 "캡처 시계 − NTP 서버 시계"다. 캡처가 뒤처져 있으면
    음수이고, 그만큼 **더해야** NTP 진실에 맞는다. 즉 부호를 뒤집는다.

    이 값을 그대로 `editcap -t <값>` 에 넘기면 된다(editcap 은 준 값을 더한다).
    """
    return -capture_minus_ntp


def build_editcap_cmd(
    src: str | Path, dst: str | Path, delta: float, *, editcap_path: str = "editcap"
) -> list[str]:
    """pcap 타임스탬프를 delta(초)만큼 이동시키는 editcap 명령을 만든다."""
    return [str(editcap_path), "-t", f"{delta:.9f}", str(src), str(dst)]


def shift_pcap_file(
    src: str | Path,
    dst: str | Path,
    delta: float,
    *,
    editcap_path: str = "editcap",
    dry_run: bool = False,
    timeout: int | None = None,
) -> None:
    """pcap 한 개의 타임스탬프를 delta 만큼 이동해 새 파일로 쓴다.

    원본은 건드리지 않는다. editcap 이 실패하면 RuntimeError 를 던지고,
    만들다 만 출력 파일은 지운다(반쪽 파일을 남기지 않는다).
    """
    dst = Path(dst)
    if dry_run:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    cmd = build_editcap_cmd(src, dst, delta, editcap_path=editcap_path)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        dst.unlink(missing_ok=True)
        raise RuntimeError(f"editcap 실패 ({src}): {proc.stderr.strip()[:300]}")


def paths_overlap(a: Path, b: Path) -> bool:
    """두 디렉터리가 겹치는지(같거나 한쪽이 다른 쪽을 포함) 판정한다.

    입력 트리와 출력 트리는 어느 방향으로든 겹치면 안 된다.
    - out 이 입력 **안**  : 재실행 시 보정본을 다시 보정한다.
    - out 이 입력 **위**  : `outdir/<rel>` 이 입력의 형제 원본과 충돌해
                            내용을 통째로 덮어쓴다.
    """
    a_res, b_res = a.resolve(), b.resolve()
    return a_res.is_relative_to(b_res) or b_res.is_relative_to(a_res)


def plan_output_paths(
    files: list[Path], base: Path, outdir: Path
) -> tuple[list[tuple[Path, Path]], list[Path]]:
    """(원본, 출력) 경로 쌍을 미리 계산하고, outdir 밖으로 나가는 것을 골라낸다.

    Returns:
        (안전한 쌍 목록, outdir 를 벗어나는 원본 목록)

    쓰기 전에 전수 검사하기 위한 함수다. 한 건이라도 벗어나면 호출자가
    아무것도 쓰지 않고 중단해야 한다 — 부분 기록을 남기면 안 된다.
    """
    base_res = base.resolve()
    out_res = outdir.resolve()
    pairs: list[tuple[Path, Path]] = []
    escaped: list[Path] = []
    for src in files:
        try:
            rel = src.resolve().relative_to(base_res)
        except ValueError:
            escaped.append(src)
            continue
        dst = outdir / rel
        if not dst.resolve().is_relative_to(out_res):
            escaped.append(src)
            continue
        pairs.append((src, dst))
    return pairs, escaped
