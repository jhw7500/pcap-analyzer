"""분석 결과를 AI 프롬프트로 변환."""
import json

def build_review_prompt(structured: dict) -> str:
    """분석 결과 요약을 4000토큰 이내 프롬프트로 변환."""
    ov = structured.get("overview", {})
    ping = structured.get("ping", {})
    roaming = structured.get("roaming", {})
    signal = structured.get("signal", {})
    delays = structured.get("delay_zones", {})
    anomalies = structured.get("anomaly_frames", {})

    summary = []
    summary.append(f"## 분석 개요")
    summary.append(f"- 총 프레임: {ov.get('total_frames', 0):,}")
    summary.append(f"- 캡처 시간: {ov.get('duration_sec', 0)}초")
    summary.append(f"- Retry율: {ov.get('retry_pct', 0)}%")
    summary.append(f"- 디바이스: {len(ov.get('devices', []))}대")

    # 로밍
    seqs = roaming.get("sequences", [])
    if seqs:
        slow = [s for s in seqs if s.get("is_slow")]
        summary.append(f"\n## 로밍")
        summary.append(f"- 총 {len(seqs)}회, 느린 로밍(>100ms) {len(slow)}회")
        if slow:
            summary.append(f"- 최대 gap: {max(s['gap_ms'] for s in seqs):.1f}ms")

    # Ping
    pairs = ping.get("pairs", [])
    losses = ping.get("losses", [])
    if pairs or losses:
        total = len(pairs) + len(losses)
        summary.append(f"\n## Ping")
        summary.append(f"- 응답: {len(pairs)}건, 미응답: {len(losses)}건 ({len(losses)*100/total:.1f}% loss)")
        if pairs:
            rtts = [p["rtt_ms"] for p in pairs]
            summary.append(f"- RTT: min={min(rtts):.1f}ms, avg={sum(rtts)/len(rtts):.1f}ms, max={max(rtts):.1f}ms")

    # 신호
    stas = signal.get("stas", {})
    if stas:
        summary.append(f"\n## 신호")
        for name, sta in stas.items():
            summary.append(f"- {name}: RSSI avg={sta.get('rssi_avg')}dBm, {sta.get('frame_count')} frames")

    # 지연 구간
    zones = delays.get("zones", []) if isinstance(delays, dict) else []
    if zones:
        summary.append(f"\n## 지연 구간: {len(zones)}건")
        for z in zones[:5]:
            summary.append(f"- {z.get('duration_sec', 0):.1f}초, 원인: {z.get('cause', '불명')}, 영향 ping: {z.get('affected_pings', 0)}건")

    # 이상 프레임
    events = anomalies.get("events", []) if isinstance(anomalies, dict) else []
    if events:
        summary.append(f"\n## 이상 프레임: {len(events)}건")
        for e in events[:5]:
            summary.append(f"- [{e.get('severity', '?')}] {e.get('type', '?')}: {e.get('description', '')}")

    prompt = "\n".join(summary)
    prompt += "\n\n위 WLAN pcap 분석 결과를 검토하고 다음을 제시하세요:\n"
    prompt += "1. 가장 심각한 문제 3개 (우선순위 순)\n"
    prompt += "2. 각 문제의 원인 추정\n"
    prompt += "3. 구체적 조치 방안 (파라미터 값, 설정 변경 등)\n"
    prompt += "4. 전체적인 네트워크 상태 평가 (양호/주의/위험)\n"
    return prompt
