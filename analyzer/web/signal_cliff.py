"""RSSI 급변(cliff) 탐지."""
from bisect import bisect_right
from typing import Any, Dict, Optional


def _drop_from(point: Dict[str, Any]) -> Optional[float]:
    """cliff 판정의 '하락 전' 대표값 — 버킷 최대값(없으면 대표 rssi).

    rssi_timeline은 1초 버킷 집계다(`structured._bucket_rssi_timeline`). 버킷
    평균끼리 비교하면 1초 안에서 일어난 급락이 평균에 묻혀 사라진다. 버킷
    최대 → 이후 버킷 최소를 비교해야 원샘플 시계열에서 '5초 내 임의의 두 샘플
    간 10dB 하락'을 잡던 감도를 잃지 않는다(과소 탐지 = 실제 신호 절벽을
    놓치는 것이므로 과다 탐지보다 위험하다).

    구버전 결과(프레임당 원샘플)에는 rssi_max가 없어 rssi로 폴백한다 — 그 경우
    값 자체가 원샘플이라 이전과 완전히 동일하게 판정된다.
    """
    value = point.get("rssi_max")
    return point.get("rssi") if value is None else value


def _drop_to(point: Dict[str, Any]) -> Optional[float]:
    """cliff 판정의 '하락 후' 대표값 — 버킷 최소값(없으면 대표 rssi)."""
    value = point.get("rssi_min")
    return point.get("rssi") if value is None else value


def analyze_signal_cliffs(signal_data: Dict[str, Any]) -> Dict[str, Any]:
    """STA별 RSSI cliff 이벤트를 계산한다.

    이전에는 이동평균(`moving_avg`)도 함께 담았지만 프론트·리포트·AI 어디에서도
    읽지 않으면서 RSSI 샘플당 dict를 하나씩 만들어, 2시간 캡처 결과 JSON에서만
    26MB를 차지했다 — 소비자가 0건이라 제거했다(프론트 timeline.js는 이미 자체
    구간 평균선을 만든다).
    """
    result = {}
    for sta_name, sta_info in signal_data.get("stas", {}).items():
        timeline = sta_info.get("rssi_timeline", [])
        if len(timeline) < 10:
            result[sta_name] = {"cliffs": []}
            continue

        # Cliff 탐지: 5초 내 10dBm 이상 하락
        cliffs = []
        i = 0
        while i < len(timeline):
            rssi_i = _drop_from(timeline[i])
            if rssi_i is None:
                i += 1
                continue
            # 자기 버킷 안에서 시작하고 끝난 급락(1초 미만)은 이 루프가 보지 못한다 —
            # 아래 별도 패스에서 처리한다. 여기서 j=i부터 보게 하면 skip-ahead(i = j)가
            # 무력화돼 건너뛰던 구간이 다시 스캔되고, 같은 절벽이 여러 번 계상된다
            # (실측 2시간 캡처에서 STA당 2,419건 → 4,310건으로 부풀었다).
            j = i + 1
            while j < len(timeline) and timeline[j]["epoch"] - timeline[i]["epoch"] <= 5.0:
                rssi_j = _drop_to(timeline[j])
                if rssi_j is not None and rssi_i - rssi_j >= 10:
                    cliffs.append({
                        "epoch": timeline[i]["epoch"],
                        "rssi_before": rssi_i,
                        "rssi_after": rssi_j,
                        "drop_db": rssi_i - rssi_j,
                        "duration_sec": round(timeline[j]["epoch"] - timeline[i]["epoch"], 2),
                    })
                    i = j  # skip ahead
                    break
                j += 1
            i += 1

        # 버킷 **내부** 급락 — 1초 안에서 떨어졌다 회복한 경우.
        # rssi_timeline이 1초 버킷 집계로 바뀌면서 위 루프로는 어느 쌍과도 비교되지
        # 않아 통째로 사라졌다(원샘플 시절에는 잡히던 하락이다). 버킷이 min/max를
        # 함께 담고 있으므로 자기 버킷의 max↔min만 보면 복원된다.
        #
        # **별도 패스인 이유**: 위 루프에 끼워 넣으면 skip-ahead가 무력화돼 같은
        # 절벽이 중복 계상된다. 그리고 이미 보고된 절벽 구간 **안**에 들어가는
        # 버킷은 건너뛴다 — 하강 도중의 버킷은 당연히 max-min이 크므로, 그대로
        # 세면 하나의 절벽을 구간 길이만큼 반복해서 세게 된다.
        # 위 루프는 절벽을 찾으면 끝 버킷까지 건너뛰므로(`i = j`) 보고된 구간들은
        # 서로 겹치지 않고 시작 시각 오름차순이다 — 후보 하나만 bisect로 짚으면
        # 포함 여부가 확정된다. 전수 비교(any)로 두면 버킷 7,200개 × 절벽 수천 건이라
        # 2시간 캡처에서만 수천만 번 비교가 된다.
        starts = [c["epoch"] for c in cliffs]
        ends = [c["epoch"] + c["duration_sec"] for c in cliffs]
        for point in timeline:
            hi, lo = _drop_from(point), _drop_to(point)
            if hi is None or lo is None or hi - lo < 10:
                continue
            ep = point["epoch"]
            idx = bisect_right(starts, ep) - 1
            if idx >= 0 and ends[idx] >= ep:
                continue
            cliffs.append({
                "epoch": ep,
                "rssi_before": hi,
                "rssi_after": lo,
                "drop_db": hi - lo,
                "duration_sec": 0.0,     # 같은 버킷 = 1초 미만
            })
        cliffs.sort(key=lambda c: c["epoch"])

        result[sta_name] = {"cliffs": cliffs}

    return result
