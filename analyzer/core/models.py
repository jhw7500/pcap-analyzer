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
    nss: str = ""  # 공간 스트림 수 원본값. VHT/HE/EHT만 채워지고 HT는 MCS에서 파생
    # (nss_int 참고). HE는 "0x0002" 형태 hex.
    data_rate: str = ""  # Mbps (legacy 송신 식별용)
    icmp_ident: str = ""  # ICMP echo identifier — 같은 src/dst 안의 흐름 구분용
    reason_code: str = ""  # wlan.fixed.reason_code — Deauth/Disassoc 사유 코드 (디버그 증거용)
    current_ap: str = ""  # wlan.fixed.current_ap — Reassoc Request의 직전 AP (로밍 전 AP)
    channel_freq: str = ""  # radiotap.channel.freq — 채널 주파수 MHz (채널/밴드 판별용)
    eapol_msgnr: str = ""  # wlan_rsna_eapol.keydes.msgnr — EAPOL 4-way 메시지 번호 1~4
    tsf: str = ""  # wlan.fixed.timestamp — 비콘의 AP TSF(µs). 캡처 간 오프셋 추정용 (merge.py)
    source: str = ""  # 캡처 출처 태그 (w1/w2/… — 다중 무선 병합 시 pipeline이 채움)
    orig_number: int = 0  # 병합 재번호 직전의 원본 tshark frame.number. 0 = 재번호 안 됨
    # (단일 소스 또는 dedup 그룹의 비-대표 프레임). 다중 소스 병합 대표 프레임만
    # merge.merge_captures가 재번호(number 덮어쓰기) 직전에 스탬프한다 —
    # per_source(소스별 원본 리스트)로 역추적할 때 "이 대표가 원래 그 소스에서
    # 몇 번 프레임이었는지" 복원하려면 `orig_number or number`를 쓴다(PR #23
    # 리뷰 6라운드 Finding B).

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
    def nss_int(self) -> Optional[int]:
        """공간 스트림 수(NSS). 알 수 없으면 None.

        PHY마다 출처가 다르다:
        - VHT/HE/EHT: 캡처가 실어준 값(self.nss). HE는 "0x0002" 형태 hex.
        - HT(11n): Wireshark에 NSS 필드가 없다. HT MCS 0~31은 8개 단위로 스트림
          수가 올라가는 정의(0~7=1SS, 8~15=2SS, …)라 인덱스에서 복원한다.
          MCS32는 HT duplicate로 1SS. MCS33 이상(unequal modulation)은 이 규칙이
          성립하지 않아 None으로 남긴다.
        - Legacy: 개념 자체가 없어 None.

        주의: VHT/HE/EHT 필드는 엄밀히 NSTS(space-time streams)라 STBC를 쓰면
        NSTS = 2×NSS다. 실측 캡처 대부분은 STBC 미사용이라 값이 일치한다.
        """
        if self.mcs_phy == "HT":
            m = self.mcs_int
            if m is None:
                return None
            if m == 32:
                return 1
            if 0 <= m <= 31:
                return m // 8 + 1
            return None
        if not self.nss:
            return None
        first = self.nss.split(",")[0].strip()
        if not first:
            return None
        try:
            value = int(first, 16) if first.lower().startswith("0x") else int(first)
        except (ValueError, IndexError):
            return None
        # radiotap HE NSTS의 0은 "미상"이다 — 스트림 0개가 아니라 정보 없음.
        return value if value > 0 else None

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
