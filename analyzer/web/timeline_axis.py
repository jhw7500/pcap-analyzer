"""디버그 모드 타임라인용 공유 시간축(shared time axis) 빌더.

디버그 화면은 RSSI / retry / ping(성공·손실) / roaming 시계열을 **하나의 공통
시간축** 위에 겹쳐 그린다. 각 데이터 소스는 epoch(초 단위 float) 키 이름이 제각각
이므로(`epoch`, `auth_epoch`, `start_epoch` 등), 모든 소스를 동일한 스케일에 정렬
하려면 먼저 전 소스를 포괄하는 정규화된 공통 시간 윈도우/그리드가 필요하다.

`build_time_axis`가 그 그리드(start, end, bins)를 만들고, `bin_index_for`가 임의의
epoch을 그 그리드 위 bin 인덱스로 매핑해 서로 다른 소스를 같은 스케일로 정렬한다.
"""
import math
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Union

# 소스마다 epoch을 담는 키 이름이 다르다. structured.py의 실제 시계열들과 호환:
#   signal rssi_timeline / per_second / ping pairs·losses → "epoch"
#   roaming sequences → "auth_epoch" / "assoc_epoch"
#   delay/anomaly zones → "start_epoch" / "end_epoch"
DEFAULT_EPOCH_KEYS = (
    "epoch",
    "ts",
    "auth_epoch",
    "assoc_epoch",
    "start_epoch",
    "end_epoch",
)

# 기본 그리드 해상도: 시계열을 적당한 개수의 bin으로 쪼갠다. (대용량 캡처
# 다운샘플링은 후속 슬라이스 범위이므로 여기서는 단순 목표 bin 수만 둔다.)
DEFAULT_TARGET_BINS = 60

Source = Iterable[Union[int, float, Dict[str, Any]]]


def iter_epochs(
    source: Source, epoch_keys: Sequence[str] = DEFAULT_EPOCH_KEYS
) -> Iterator[float]:
    """단일 소스에서 epoch(float)들을 추출한다.

    소스 항목은 raw 숫자이거나, epoch을 키로 갖는 dict일 수 있다. dict인 경우
    `epoch_keys`에 나열된 모든 키의 값을 (있으면) 방출한다 — roaming sequence처럼
    한 항목이 여러 시점(auth/assoc)을 갖는 경우 둘 다 시간축에 반영하기 위함.
    """
    for item in source:
        if isinstance(item, bool):
            # bool은 int의 하위형이지만 epoch이 아니므로 제외.
            continue
        if isinstance(item, (int, float)):
            yield float(item)
        elif isinstance(item, dict):
            for key in epoch_keys:
                value = item.get(key)
                if isinstance(value, bool):
                    continue
                if isinstance(value, (int, float)):
                    yield float(value)


def collect_epochs(
    sources: Sequence[Source], epoch_keys: Sequence[str] = DEFAULT_EPOCH_KEYS
) -> List[float]:
    """여러 소스를 가로질러 모든 epoch을 모은다."""
    epochs: List[float] = []
    for source in sources:
        if source is None:
            continue
        epochs.extend(iter_epochs(source, epoch_keys))
    return epochs


def build_time_axis(
    sources: Sequence[Source],
    bin_size_sec: Optional[float] = None,
    bin_count: Optional[int] = None,
    epoch_keys: Sequence[str] = DEFAULT_EPOCH_KEYS,
) -> Dict[str, Any]:
    """모든 소스를 포괄하는 정규화된 공통 시간축을 만든다.

    Args:
        sources: 시계열 소스들의 리스트. 각 소스는 숫자(epoch) 또는 epoch 키를 갖는
            dict의 시퀀스. (예: signal rssi_timeline, ping pairs/losses,
            roaming sequences, per_second timeline)
        bin_size_sec: bin 하나의 길이(초). 지정 시 이 값을 우선 사용.
        bin_count: bin 개수. bin_size_sec 미지정 시 사용. 둘 다 없으면 기본 목표
            bin 수(DEFAULT_TARGET_BINS)로 자동 산정.
        epoch_keys: dict 소스에서 epoch을 읽을 키 이름들.

    Returns:
        {
            "start": float,            # 전 소스 최소 epoch
            "end": float,              # 전 소스 최대 epoch
            "duration_sec": float,     # end - start
            "bin_size_sec": float,     # bin 하나의 길이(초)
            "bin_count": int,          # bin 개수
            "bins": [float, ...],      # 각 bin의 왼쪽 경계 epoch (length == bin_count)
            "empty": bool,             # epoch이 하나도 없으면 True
        }

    빈 입력이면 모든 수치 0의 빈 축을 반환한다(`empty=True`).
    """
    epochs = collect_epochs(sources, epoch_keys)

    if not epochs:
        return {
            "start": 0.0,
            "end": 0.0,
            "duration_sec": 0.0,
            "bin_size_sec": 0.0,
            "bin_count": 0,
            "bins": [],
            "empty": True,
        }

    start = min(epochs)
    end = max(epochs)
    duration = end - start

    # 모든 epoch이 동일한 한 점(점 소스) → bin 하나짜리 축.
    if duration <= 0:
        return {
            "start": start,
            "end": end,
            "duration_sec": 0.0,
            "bin_size_sec": 0.0,
            "bin_count": 1,
            "bins": [start],
            "empty": False,
        }

    if bin_size_sec is not None and bin_size_sec > 0:
        size = float(bin_size_sec)
        count = max(1, math.ceil(duration / size))
    else:
        if bin_count is not None and bin_count > 0:
            count = int(bin_count)
        else:
            count = DEFAULT_TARGET_BINS
        size = duration / count

    bins = [start + i * size for i in range(count)]

    return {
        "start": start,
        "end": end,
        "duration_sec": duration,
        "bin_size_sec": size,
        "bin_count": count,
        "bins": bins,
        "empty": False,
    }


def bin_index_for(axis: Dict[str, Any], epoch: float) -> int:
    """epoch을 공유 축의 bin 인덱스로 매핑한다(같은 스케일 정렬).

    서로 다른 소스라도 같은 `axis`를 통과시키면 동일한 그리드 인덱스를 얻으므로
    한 시간축 위에 정렬된다. 결과는 항상 [0, bin_count-1] 범위로 clamp 된다.
    """
    count = axis.get("bin_count", 0)
    if count <= 0:
        return 0
    size = axis.get("bin_size_sec", 0.0)
    start = axis.get("start", 0.0)
    if size <= 0:
        return 0
    idx = int((epoch - start) / size)
    if idx < 0:
        return 0
    if idx >= count:
        return count - 1
    return idx
