"""이상 프레임 탐지 모듈 — DeAuth/DisAssoc, 과도한 ProbeReq, ARP storm 등을 감지한다."""
from typing import Any, Dict, List


def detect_anomalies(overview_data: Dict[str, Any]) -> Dict[str, Any]:
    """overview 구조화 데이터에서 이상 프레임 이벤트를 탐지한다.

    Returns:
        {"anomalies": [...], "summary": {...}}
    """
    anomalies: List[Dict] = []
    total_frames = overview_data.get("total_frames", 0)
    subtype_dist = overview_data.get("subtype_dist", {})
    protocol_dist = overview_data.get("protocol_dist", {})

    if total_frames == 0:
        return {"anomalies": [], "summary": {"total_anomalies": 0}}

    # 1. DeAuth/DisAssoc 프레임 탐지 (subtype 10=DisAssoc, 12=DeAuth)
    deauth_count = subtype_dist.get("12", 0)
    disassoc_count = subtype_dist.get("10", 0)
    deauth_total = deauth_count + disassoc_count

    if deauth_total > 0:
        severity = "high" if deauth_total > 10 else "medium" if deauth_total > 3 else "low"
        anomalies.append({
            "type": "deauth_disassoc",
            "severity": severity,
            "description": f"DeAuth({deauth_count})/DisAssoc({disassoc_count}) 프레임 감지",
            "count": deauth_total,
            "recommendation": "비인가 연결 해제 공격 또는 AP 강제 퇴출 여부 확인 필요",
        })

    # 2. 과도한 ProbeReq 탐지 (subtype 4)
    probe_req_count = subtype_dist.get("4", 0)
    probe_pct = (probe_req_count / total_frames * 100) if total_frames > 0 else 0

    if probe_pct > 5.0:
        severity = "high" if probe_pct > 20 else "medium" if probe_pct > 10 else "low"
        anomalies.append({
            "type": "excessive_probe_req",
            "severity": severity,
            "description": f"ProbeReq가 전체 프레임의 {probe_pct:.1f}%({probe_req_count}건)로 과다",
            "count": probe_req_count,
            "recommendation": "스캐닝 빈도 조정 또는 비인가 디바이스 탐색 확인",
        })

    # 3. ARP storm 탐지
    arp_count = protocol_dist.get("ARP", 0)
    arp_pct = (arp_count / total_frames * 100) if total_frames > 0 else 0

    if arp_pct > 2.0:
        severity = "high" if arp_pct > 10 else "medium" if arp_pct > 5 else "low"
        anomalies.append({
            "type": "arp_storm",
            "severity": severity,
            "description": f"ARP 트래픽이 전체의 {arp_pct:.1f}%({arp_count}건)로 비정상적으로 높음",
            "count": arp_count,
            "recommendation": "ARP 스푸핑 또는 네트워크 루프 여부 점검 필요",
        })

    return {
        "anomalies": anomalies,
        "summary": {
            "total_anomalies": len(anomalies),
            "high_severity": sum(1 for a in anomalies if a["severity"] == "high"),
            "medium_severity": sum(1 for a in anomalies if a["severity"] == "medium"),
            "low_severity": sum(1 for a in anomalies if a["severity"] == "low"),
        },
    }
