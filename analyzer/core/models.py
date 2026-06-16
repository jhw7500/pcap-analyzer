"""pcap 분석을 위한 데이터 모델"""
from dataclasses import dataclass
from typing import Optional, List

SUBTYPE_NAMES = {
    "0": "AssocReq", "1": "AssocResp", "2": "ReassocReq", "3": "ReassocResp",
    "4": "ProbeReq", "5": "ProbeResp", "8": "Beacon", "10": "DisAssoc",
    "11": "Auth", "12": "DeAuth", "13": "Action",
    "14": "ActionNoAck",
    "18": "Trigger", "21": "VHT NDP Ann",
    "24": "BAR", "25": "BA", "27": "RTS", "28": "CTS", "29": "ACK",
    "30": "CF-End", "37": "VHT NDP Ann",
    "32": "Data", "40": "QoS Data", "44": "QoS Null",
}

DATA_SUBTYPES = {"32", "40", "44"}
MGMT_SUBTYPES = {"0", "1", "2", "3", "4", "5", "8", "10", "11", "12", "13", "14"}
CTRL_SUBTYPES = {"18", "21", "24", "25", "27", "28", "29", "30", "37"}
ROAMING_SUBTYPES = {"0", "1", "2", "3", "11", "12"}


@dataclass
class Frame:
    number: int
    epoch: float
    timestamp: str
    retry: bool
    subtype: str
    protocol: str
    length: int
    mcs: str
    rssi: str
    ta: str
    ra: str
    ip_src: str
    ip_dst: str
    icmp_type: str
    arp_opcode: str
    tcp_len: str
    tcp_flags: str
    seq: str
    icmp_seq: str = ""
    bssid: str = ""
    mcs_phy: str = ""  # "HT" | "VHT" | "HE" | "EHT" | "Legacy" — mcs 값 출처
    data_rate: str = ""  # Mbps (legacy 송신 식별용)
    icmp_ident: str = ""  # ICMP echo identifier — 같은 src/dst 안의 흐름 구분용
    reason_code: str = ""  # wlan.fixed.reason_code — Deauth/Disassoc 사유 코드 (디버그 증거용)
    current_ap: str = ""  # wlan.fixed.current_ap — Reassoc Request의 직전 AP (로밍 전 AP)

    @property
    def subtype_name(self) -> str:
        return SUBTYPE_NAMES.get(self.subtype, f"type={self.subtype}")

    @property
    def is_data(self) -> bool:
        return self.subtype in DATA_SUBTYPES

    @property
    def is_mgmt(self) -> bool:
        return self.subtype in MGMT_SUBTYPES

    @property
    def is_ctrl(self) -> bool:
        return self.subtype in CTRL_SUBTYPES

    @property
    def frame_type(self) -> str:
        if self.is_mgmt:
            return "Management"
        if self.is_ctrl:
            return "Control"
        if self.is_data:
            return "Data"
        return "Other"

    @property
    def is_roaming_related(self) -> bool:
        return self.subtype in ROAMING_SUBTYPES or self.protocol == "EAPOL"

    @property
    def is_arp(self) -> bool:
        return bool(self.arp_opcode)

    @property
    def is_icmp_request(self) -> bool:
        return self.icmp_type == "8"

    @property
    def is_icmp_reply(self) -> bool:
        return self.icmp_type == "0"

    @property
    def is_pure_tcp_ack(self) -> bool:
        return self.tcp_len == "0" and bool(self.tcp_flags)

    @property
    def is_control_traffic(self) -> bool:
        return self.is_arp or bool(self.icmp_type) or self.is_pure_tcp_ack

    @property
    def rssi_first(self) -> Optional[int]:
        if not self.rssi:
            return None
        try:
            return int(self.rssi.split(",")[0])
        except (ValueError, IndexError):
            return None

    @property
    def mcs_int(self) -> Optional[int]:
        if not self.mcs:
            return None
        first = self.mcs.split(",")[0].strip()
        if not first:
            return None
        try:
            # HE(802.11ax) radiotap.he.data_3.data_mcs는 "0x0007" 형태 hex로 옴
            if first.lower().startswith("0x"):
                return int(first, 16)
            return int(first)
        except (ValueError, IndexError):
            return None

    @property
    def time_short(self) -> str:
        for part in self.timestamp.split(" "):
            if ":" in part and "." in part and part.count(":") == 2:
                return part[:15]
        return self.timestamp


@dataclass
class AnalysisSection:
    title: str
    lines: List[str]
    summary: str = ""
