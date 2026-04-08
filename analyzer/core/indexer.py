"""프레임 사전 인덱싱 — O(N) 한 번으로 모든 분석 모듈이 O(1)~O(log N) 접근 가능"""
from bisect import bisect_left, bisect_right
from collections import defaultdict
from typing import List, Dict, Tuple
from .models import Frame


class FrameIndex:
    """전체 프레임에 대한 사전 인덱스.

    한 번 O(N)으로 구축하면 이후 접근은 O(1) 또는 O(log N).
    """

    def __init__(self, frames: List[Frame], roles: Dict):
        self.frames = frames
        self.epochs = [f.epoch for f in frames]

        # STA별 프레임 인덱스
        self.by_sta: Dict[str, List[Frame]] = defaultdict(list)
        # STA별 epoch 배열 (bisect용)
        self.sta_epochs: Dict[str, List[float]] = defaultdict(list)
        # AP별 프레임 (BSSID 기반)
        self.by_ap_bssid: Dict[str, List[Frame]] = defaultdict(list)
        # TA/RA별 프레임
        self.by_ta: Dict[str, List[Frame]] = defaultdict(list)
        self.by_ra: Dict[str, List[Frame]] = defaultdict(list)
        # 로밍 관련 프레임 (epoch 정렬)
        self.roaming_frames: List[Frame] = []

        sta_macs = {m for m, r in roles.items() if r["role"] == "STA"}
        ap_macs = {m for m, r in roles.items() if r["role"] == "AP"}

        for f in frames:
            # STA 인덱스: TA 또는 RA가 STA인 프레임
            if f.ta in sta_macs:
                self.by_sta[f.ta].append(f)
                self.sta_epochs[f.ta].append(f.epoch)
            if f.ra in sta_macs and f.ra != f.ta:
                self.by_sta[f.ra].append(f)
                self.sta_epochs[f.ra].append(f.epoch)

            # AP 인덱스 (BSSID 기반)
            if f.bssid in ap_macs:
                self.by_ap_bssid[f.bssid].append(f)

            # TA/RA 인덱스
            if f.ta:
                self.by_ta[f.ta].append(f)
            if f.ra:
                self.by_ra[f.ra].append(f)

            # 로밍 프레임
            if f.is_roaming_related:
                self.roaming_frames.append(f)

    def frames_in_window(self, center: float, before: float, after: float) -> Tuple[List[Frame], List[Frame]]:
        """center 기준 전후 시간 윈도우의 프레임을 bisect로 O(log N) 조회."""
        i_start = bisect_left(self.epochs, center - before)
        i_center = bisect_left(self.epochs, center)
        i_end = bisect_right(self.epochs, center + after)
        return self.frames[i_start:i_center], self.frames[i_center:i_end]

    def sta_frames_in_window(self, sta: str, center: float,
                             before: float, after: float) -> Tuple[List[Frame], List[Frame]]:
        """특정 STA의 전후 프레임을 bisect로 조회."""
        epochs = self.sta_epochs.get(sta, [])
        if not epochs:
            return [], []
        all_f = self.by_sta.get(sta, [])

        i_start = bisect_left(epochs, center - before)
        i_center = bisect_left(epochs, center)
        i_end = bisect_right(epochs, center + after)
        return all_f[i_start:i_center], all_f[i_center:i_end]

    def nearest_roaming(self, epoch: float, max_gap: float = 5.0):
        """가장 가까운 로밍 프레임을 bisect로 O(log N) 조회."""
        if not self.roaming_frames:
            return None
        roam_epochs = [f.epoch for f in self.roaming_frames]
        idx = bisect_left(roam_epochs, epoch)
        best = None
        best_gap = max_gap
        for i in (idx - 1, idx):
            if 0 <= i < len(self.roaming_frames):
                gap = abs(self.roaming_frames[i].epoch - epoch)
                if gap < best_gap:
                    best = self.roaming_frames[i]
                    best_gap = gap
        return best
