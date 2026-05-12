"""tshark를 실행하여 pcap에서 프레임 데이터를 추출한다."""

import functools
import re
import subprocess
import sys
import tempfile
import threading
import time
import importlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Frame as FrameType
else:
    FrameType = Any

try:
    from .models import Frame
except ImportError:
    Frame = importlib.import_module("models").Frame

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.time",
    "wlan.fc.retry",
    "wlan.fc.type_subtype",
    "_ws.col.Protocol",
    "frame.len",
    "radiotap.mcs.index",  # 802.11n (HT) MCS — cols[7]
    "radiotap.dbm_antsignal",
    "wlan.ta",
    "wlan.ra",
    "wlan.bssid",
    "ip.src",
    "ip.dst",
    "icmp.type",
    "arp.opcode",
    "tcp.len",
    "tcp.flags",
    "wlan.seq",
    "icmp.seq",
    # PHY별 MCS — 자동차 칩셋(802.11ac/ax)에선 radiotap.mcs.index가 비고 wlan_radio 쪽에 들어감
    "wlan_radio.11n.mcs_index",   # cols[20]
    "wlan_radio.11ac.mcs",        # cols[21]
    "wlan_radio.11be.mcs",        # cols[22]
    "radiotap.he.data_3.data_mcs",  # cols[23] — 802.11ax (HE) MCS
    "wlan_radio.data_rate",       # cols[24] — Mbps (legacy 폴백 표시용)
]


def _cleanup_stderr_file(stderr_file) -> None:
    """tshark stderr 캡처용 임시 파일 정리."""
    try:
        stderr_file.close()
    except Exception:
        pass
    try:
        Path(stderr_file.name).unlink(missing_ok=True)
    except Exception:
        pass


_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def detect_tshark_version(tshark_path: str = "tshark") -> Dict[str, str]:
    """tshark --version 출력에서 버전 정보를 추출.

    감지 실패 시 version="unknown"으로 반환. 예외를 던지지 않는다.
    """
    try:
        result = subprocess.run(
            [tshark_path or "tshark", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        first_line = (result.stdout or "").split("\n", 1)[0].strip()
        match = _VERSION_RE.search(first_line)
        return {
            "path": tshark_path or "",
            "version": match.group(1) if match else "unknown",
            "raw": first_line,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, ValueError):
        return {"path": tshark_path or "", "version": "unknown", "raw": ""}


def _normalize_retry(value: str) -> bool:
    first = value.split(",")[0].strip().lower()
    return first in {"1", "true", "yes"}


def _normalize_subtype(value: str) -> str:
    first = value.split(",")[0].strip()
    if not first:
        return ""
    try:
        if first.lower().startswith("0x"):
            return str(int(first, 16))
        return str(int(first))
    except ValueError:
        return first


@functools.lru_cache(maxsize=8)
def _get_supported_fields(tshark_path: str) -> frozenset:
    """tshark가 인식하는 필드 이름 집합. (tshark -G fields 출력 파싱, lru_cache로 1회 호출)"""
    try:
        result = subprocess.run(
            [tshark_path, "-G", "fields"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return frozenset()
    if result.returncode != 0:
        return frozenset()
    # 'F\t<display_name>\t<field_name>\t...' 형식
    names = set()
    for line in result.stdout.splitlines():
        if line.startswith("F\t"):
            parts = line.split("\t")
            if len(parts) >= 3:
                names.add(parts[2])
    return frozenset(names)


# tshark column-alias 필드들은 -G fields 출력에 enumerate 안 되지만
# column resolver가 항상 처리. capability check에서 자동 supported 처리.
_COLUMN_ALIAS_PREFIX = "_ws.col."


def _filter_unsupported_fields(tshark_path: str) -> tuple:
    """TSHARK_FIELDS를 호스트 tshark가 지원하는 것만 추려서 반환.

    Returns (used_fields, dropped_fields, dropped_indices). dropped_indices는
    원본 TSHARK_FIELDS에서의 인덱스 위치(extract_frames가 빈 컬럼 padding에 사용).
    capability detection 실패(empty supported set) 시에는 원본 그대로 반환.
    _ws.col.* 같은 column alias 필드는 -G fields에 enumerate 안 되지만 항상 동작 → 자동 통과.
    """
    supported = _get_supported_fields(tshark_path)
    if not supported:
        return list(TSHARK_FIELDS), [], []

    def _is_supported(field: str) -> bool:
        return field in supported or field.startswith(_COLUMN_ALIAS_PREFIX)

    used = [f for f in TSHARK_FIELDS if _is_supported(f)]
    dropped = [f for f in TSHARK_FIELDS if not _is_supported(f)]
    dropped_indices = [TSHARK_FIELDS.index(f) for f in dropped]
    return used, dropped, dropped_indices


def build_tshark_cmd(
    pcap_path: str,
    wpa_passphrase: str = "",
    ssid: str = "",
    time_start: str = "",
    time_end: str = "",
    mac_filter: str = "",
    ip_filter: str = "",
    tshark_path: str = "tshark",
    fields: Optional[List[str]] = None,
) -> List[str]:
    cmd = [tshark_path or "tshark", "-r", pcap_path, "-T", "fields"]
    field_list = fields if fields is not None else TSHARK_FIELDS
    for field in field_list:
        cmd.extend(["-e", field])

    if wpa_passphrase and ssid:
        wpa_key = f"{wpa_passphrase}:{ssid}"
        cmd.extend(
            [
                "-o",
                "wlan.enable_decryption:TRUE",
                "-o",
                f'uat:80211_keys:"wpa-pwd","{wpa_key}"',
            ]
        )

    filters: List[str] = []
    if time_start:
        filters.append(f'frame.time >= "{time_start}"')
    if time_end:
        filters.append(f'frame.time < "{time_end}"')
    if mac_filter:
        # wlan.addr는 TA/RA 모두 매칭
        mac_parts = [f"wlan.addr == {m.strip()}" for m in mac_filter.split(",")]
        filters.append(f"({' || '.join(mac_parts)})")
    if ip_filter:
        ip_parts = [f"ip.addr == {ip.strip()}" for ip in ip_filter.split(",")]
        filters.append(f"({' || '.join(ip_parts)})")
    if filters:
        cmd.extend(["-Y", " && ".join(filters)])

    return cmd


def parse_tsv_line(line: str) -> Optional[FrameType]:
    cols = line.strip().split("\t")
    expected = len(TSHARK_FIELDS)
    if len(cols) < 7:
        return None
    while len(cols) < expected:
        cols.append("")

    try:
        # MCS: HT > VHT(11ac) > 11be > HE(11ax) 순으로 첫 non-empty.
        # 출처별 PHY 모드도 함께 추적해 device_stats의 mcs_by_phy 분리에 사용.
        ht_val = cols[7] or (cols[20] if len(cols) > 20 else "")
        vht_val = cols[21] if len(cols) > 21 else ""
        eht_val = cols[22] if len(cols) > 22 else ""
        he_val = cols[23] if len(cols) > 23 else ""
        if ht_val:
            mcs_val, mcs_phy = ht_val, "HT"
        elif vht_val:
            mcs_val, mcs_phy = vht_val, "VHT"
        elif eht_val:
            mcs_val, mcs_phy = eht_val, "EHT"
        elif he_val:
            mcs_val, mcs_phy = he_val, "HE"
        else:
            mcs_val, mcs_phy = "", "Legacy"
        data_rate = cols[24] if len(cols) > 24 else ""
        return Frame(
            number=int(cols[0]),
            epoch=float(cols[1]),
            timestamp=cols[2],
            retry=_normalize_retry(cols[3]),
            subtype=_normalize_subtype(cols[4]),
            protocol=cols[5],
            length=int(cols[6]) if cols[6] else 0,
            mcs=mcs_val,
            rssi=cols[8],
            ta=cols[9],
            ra=cols[10],
            bssid=cols[11],
            ip_src=cols[12],
            ip_dst=cols[13],
            icmp_type=cols[14],
            arp_opcode=cols[15],
            tcp_len=cols[16],
            tcp_flags=cols[17],
            seq=cols[18] if len(cols) > 18 else "",
            icmp_seq=cols[19] if len(cols) > 19 else "",
            mcs_phy=mcs_phy,
            data_rate=data_rate,
        )
    except (ValueError, IndexError):
        return None


def extract_frames(
    pcap_path: str,
    wpa_passphrase: str = "",
    ssid: str = "",
    time_start: str = "",
    time_end: str = "",
    mac_filter: str = "",
    ip_filter: str = "",
    tshark_path: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
    progress_cb: "Optional[Callable[[int], None]]" = None,
) -> List[FrameType]:
    resolved_path = tshark_path or "tshark"
    used_fields, dropped_fields, dropped_indices = _filter_unsupported_fields(resolved_path)
    if dropped_fields:
        print(
            f"[WARN] tshark({resolved_path})에 미지원 필드 자동 제외: {dropped_fields}",
            file=sys.stderr,
        )
    cmd = build_tshark_cmd(
        pcap_path,
        wpa_passphrase,
        ssid,
        time_start,
        time_end,
        mac_filter,
        ip_filter,
        tshark_path=resolved_path,
        fields=used_fields,
    )

    # 스트리밍 방식: stdout을 한 줄씩 읽어 메모리 사용량을 최소화한다.
    # stderr는 임시 파일로 캡처 — 실패 시 진짜 원인 surface (PIPE는 large stderr에서 deadlock 위험)
    stderr_file = tempfile.NamedTemporaryFile(
        mode="w+", suffix=".tshark-stderr", delete=False, encoding="utf-8"
    )
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=stderr_file, text=True, bufsize=1
    )

    # 취소 신호가 들어오면 tshark 프로세스를 즉시 종료하는 watcher 스레드
    cancelled = [False]

    def _cancel_watcher():
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled[0] = True
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                # stdout 강제 close → main loop의 readline이 즉시 EOF
                try:
                    if proc.stdout is not None:
                        proc.stdout.close()
                except Exception:
                    pass
                return
            time.sleep(0.05)

    watcher: Optional[threading.Thread] = None
    if cancel_event is not None:
        watcher = threading.Thread(target=_cancel_watcher, daemon=True)
        watcher.start()

    frames: List[FrameType] = []
    count = 0
    log_interval = 500000
    progress_interval = 5000  # progress_cb 호출 간격 (frame count 기반)

    # 시간 기반 ticker — 프레임 콜백 사이 공백을 메워 UI가 멈춰 보이지 않게
    ticker_stop = threading.Event()
    ticker_thread: Optional[threading.Thread] = None

    def _progress_ticker():
        while not ticker_stop.is_set():
            if progress_cb is not None:
                try:
                    progress_cb(count)
                except Exception:
                    pass
            if ticker_stop.wait(1.5):
                return

    if progress_cb is not None:
        ticker_thread = threading.Thread(target=_progress_ticker, daemon=True)
        ticker_thread.start()

    stdout = proc.stdout
    if stdout is None:
        ticker_stop.set()
        _cleanup_stderr_file(stderr_file)
        return []

    # 미지원 필드 인덱스(오름차순) — line 분할 후 그 위치에 빈 컬럼 insert
    sorted_dropped = sorted(dropped_indices)

    try:
        for line in stdout:
            if cancel_event is not None and cancel_event.is_set():
                break
            if sorted_dropped:
                cols = line.rstrip("\n").split("\t")
                for idx in sorted_dropped:
                    if idx <= len(cols):
                        cols.insert(idx, "")
                line = "\t".join(cols) + "\n"
            frame = parse_tsv_line(line)
            if frame is not None:
                frames.append(frame)
                count += 1
                if count % log_interval == 0:
                    print(f"  -> {count:,}프레임 처리 중...", file=sys.stderr)
                if progress_cb is not None and count % progress_interval == 0:
                    try:
                        progress_cb(count)
                    except Exception:
                        pass
    except (ValueError, OSError):
        # stdout 강제 close 시 발생 가능 — 무시하고 정상 종료 흐름으로
        pass

    ticker_stop.set()
    if ticker_thread is not None:
        ticker_thread.join(timeout=1)

    _ = proc.wait()
    if watcher is not None:
        watcher.join(timeout=1)

    if cancelled[0]:
        _cleanup_stderr_file(stderr_file)
        return []

    if proc.returncode != 0:
        stderr_content = ""
        try:
            stderr_file.flush()
            stderr_file.seek(0)
            stderr_content = stderr_file.read()
        except (OSError, ValueError):
            pass
        print(
            f"[ERROR] tshark 실행 실패 (exit code: {proc.returncode})",
            file=sys.stderr,
        )
        if stderr_content.strip():
            print(f"[ERROR] tshark stderr:", file=sys.stderr)
            for line in stderr_content.splitlines()[-30:]:
                print(f"  {line}", file=sys.stderr)
        else:
            print(f"[ERROR] tshark stderr (empty)", file=sys.stderr)
        print(f"[ERROR] 호출 명령: {' '.join(cmd)}", file=sys.stderr)
        _cleanup_stderr_file(stderr_file)
        return []

    _cleanup_stderr_file(stderr_file)
    return frames
