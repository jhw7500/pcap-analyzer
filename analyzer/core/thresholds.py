"""진단 임계값 단일 소스 (자동차 운용 기준).

동일 지표의 임계값이 SYSTEM_PROMPT·structured 진단·종합 진단에 제각각
하드코딩되어 판정이 상충하던 문제(예: retry 18.3%가 화면 '정상' / 리포트
'medium' / AI 프롬프트 '위험')를 막기 위해, 모든 소비자(ai/reviewer.py,
analyzer/web/structured.py, analyzer/core/modules/diagnosis.py 등)가
이 모듈의 상수만 참조한다.

심각도는 3단계: 'good'(양호) / 'warn'(주의) / 'danger'(위험).
경계값 자체는 항상 낮은 단계에 포함된다 (예: retry 5% → good, 15% → warn).
"""

# Retry율(%) — 차량 환경은 로밍·간섭으로 재전송이 잦지만, 5% 초과부터 체감
# 지연이 시작되고 15% 초과면 실효 스루풋 급락(자동차 운용 기준).
RETRY_WARN_PCT = 5
RETRY_DANGER_PCT = 15

# 로밍 gap(ms) — Auth→(Re)Assoc 간격. 차량 주행 중 50ms 초과면 스트리밍
# 끊김 체감 시작, 100ms 초과는 '느린 로밍'으로 핸드오버 실패에 준함.
ROAM_GAP_WARN_MS = 50
ROAM_GAP_DANGER_MS = 100

# Ping RTT 평균(ms) — 차내 제어/텔레메트리 트래픽 기준 30ms까지 양호,
# 80ms 초과면 실시간성 요구 애플리케이션에 위험.
RTT_WARN_MS = 30
RTT_DANGER_MS = 80

# Ping loss(%) — 1% 초과부터 재시도 부하 발생, 5% 초과는 링크 불안정.
LOSS_WARN_PCT = 1
LOSS_DANGER_PCT = 5

# RSSI(dBm) — -65dBm 이상이어야 HE(11ax) 고차 MCS 유지, -75dBm 미만은
# HE 송신 자체가 어려움(자동차 운용 기준).
RSSI_WARN_DBM = -65
RSSI_DANGER_DBM = -75

# HE MCS 평균 — 6 이상 양호, 3 미만이면 저차 변조 고착(링크 품질 위험).
MCS_WARN = 6
MCS_DANGER = 3


def _severity_high_bad(value, warn, danger) -> str:
    """값이 클수록 나쁜 지표의 심각도 (경계값은 낮은 단계에 포함)."""
    if value > danger:
        return "danger"
    if value > warn:
        return "warn"
    return "good"


def _severity_low_bad(value, warn, danger) -> str:
    """값이 작을수록 나쁜 지표의 심각도 (경계값은 낮은 단계에 포함)."""
    if value < danger:
        return "danger"
    if value < warn:
        return "warn"
    return "good"


def retry_severity(pct) -> str:
    """Retry율(%) → 'good'|'warn'|'danger'."""
    return _severity_high_bad(pct, RETRY_WARN_PCT, RETRY_DANGER_PCT)


def roam_gap_severity(gap_ms) -> str:
    """로밍 gap(ms) → 'good'|'warn'|'danger'|'unknown'.

    gap_ms는 **None일 수 있다** — 그 로밍의 Auth 프레임이 캡처에 없어 시작 시각을
    모르는 경우다(roaming.pair_roaming_sequences). 모르는 값을 'good'으로 낙관하면
    실제로 느렸을 수도 있는 로밍이 정상으로 보고되므로 'unknown'으로 분리한다.
    """
    if gap_ms is None:
        return "unknown"
    return _severity_high_bad(gap_ms, ROAM_GAP_WARN_MS, ROAM_GAP_DANGER_MS)


def rtt_severity(avg_ms) -> str:
    """Ping RTT 평균(ms) → 'good'|'warn'|'danger'."""
    return _severity_high_bad(avg_ms, RTT_WARN_MS, RTT_DANGER_MS)


def loss_severity(pct) -> str:
    """Ping loss(%) → 'good'|'warn'|'danger'."""
    return _severity_high_bad(pct, LOSS_WARN_PCT, LOSS_DANGER_PCT)


def rssi_severity(dbm) -> str:
    """RSSI(dBm) → 'good'|'warn'|'danger'."""
    return _severity_low_bad(dbm, RSSI_WARN_DBM, RSSI_DANGER_DBM)


def mcs_severity(mcs) -> str:
    """HE MCS 평균 → 'good'|'warn'|'danger'."""
    return _severity_low_bad(mcs, MCS_WARN, MCS_DANGER)
