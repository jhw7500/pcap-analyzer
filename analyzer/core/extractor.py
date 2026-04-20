"""tshark를 실행하여 pcap에서 프레임 데이터를 추출한다."""

import re
import subprocess
import sys
import threading
import time
import importlib
from typing import Any, Dict, List, Optional, TYPE_CHECKING

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
    "radiotap.mcs.index",
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
]


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


def build_tshark_cmd(
    pcap_path: str,
    wpa_passphrase: str = "",
    ssid: str = "",
    time_start: str = "",
    time_end: str = "",
    mac_filter: str = "",
    ip_filter: str = "",
    tshark_path: str = "tshark",
) -> List[str]:
    cmd = [tshark_path or "tshark", "-r", pcap_path, "-T", "fields"]
    for field in TSHARK_FIELDS:
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
        return Frame(
            number=int(cols[0]),
            epoch=float(cols[1]),
            timestamp=cols[2],
            retry=_normalize_retry(cols[3]),
            subtype=_normalize_subtype(cols[4]),
            protocol=cols[5],
            length=int(cols[6]) if cols[6] else 0,
            mcs=cols[7],
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
) -> List[FrameType]:
    resolved_path = tshark_path or "tshark"
    cmd = build_tshark_cmd(
        pcap_path,
        wpa_passphrase,
        ssid,
        time_start,
        time_end,
        mac_filter,
        ip_filter,
        tshark_path=resolved_path,
    )

    # 스트리밍 방식: stdout을 한 줄씩 읽어 메모리 사용량을 최소화한다.
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )

    # 취소 신호가 들어오면 tshark 프로세스를 즉시 종료하는 watcher 스레드
    cancelled = [False]

    def _cancel_watcher():
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled[0] = True
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return
            time.sleep(0.1)

    watcher: Optional[threading.Thread] = None
    if cancel_event is not None:
        watcher = threading.Thread(target=_cancel_watcher, daemon=True)
        watcher.start()

    frames: List[FrameType] = []
    count = 0
    progress_interval = 500000

    stdout = proc.stdout
    if stdout is None:
        return []

    for line in stdout:
        if cancel_event is not None and cancel_event.is_set():
            break
        frame = parse_tsv_line(line)
        if frame is not None:
            frames.append(frame)
            count += 1
            if count % progress_interval == 0:
                print(f"  -> {count:,}프레임 처리 중...", file=sys.stderr)

    _ = proc.wait()
    if watcher is not None:
        watcher.join(timeout=1)

    if cancelled[0]:
        return []

    if proc.returncode != 0:
        print(f"[ERROR] tshark 실행 실패 (exit code: {proc.returncode})", file=sys.stderr)
        return []

    return frames
