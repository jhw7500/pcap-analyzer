"""grounding-validator 단위 테스트.

근거 없는 결론(빈 frame_refs / punt 표현)을 정확히 골라내고,
모두 근거를 갖춘 출력에는 빈 리스트를 반환하는지 검증한다.
"""

from analyzer.core.modules.diagnosis import (
    Conclusion,
    TimeWindow,
    contains_punt_language,
    find_ungrounded_conclusions,
)


def _window() -> TimeWindow:
    return TimeWindow(start_epoch=1000.0, end_epoch=1005.0)


def _grounded(message: str = "높은 Retry Rate: 47.2%", refs=(42,)) -> Conclusion:
    return Conclusion(
        level="WARNING",
        message=message,
        frame_refs=list(refs),
        time_window=_window(),
    )


class TestContainsPuntLanguage:
    def test_korean_punt_phrase(self):
        assert contains_punt_language("ping loss 원인 추가 조사 필요")

    def test_english_punt_phrase_case_insensitive(self):
        assert contains_punt_language("Root cause needs Further Investigation")

    def test_unknown_cause_phrase(self):
        assert contains_punt_language("원인 미상으로 보류")

    def test_grounded_message_is_not_punt(self):
        assert not contains_punt_language("높은 Retry Rate: 47.2%")
        assert not contains_punt_language("Ping Loss 3/10 (30%)")


class TestFindUngroundedConclusions:
    def test_fully_grounded_output_returns_empty(self):
        output = [
            _grounded(refs=[1, 2]),
            _grounded(message="잦은 로밍: 5회", refs=[7]),
        ]
        assert find_ungrounded_conclusions(output) == []

    def test_zero_frame_refs_flagged(self):
        ungrounded = {"level": "WARNING", "message": "Ping Loss 발생", "frame_refs": []}
        grounded = _grounded(refs=[3])
        result = find_ungrounded_conclusions([grounded, ungrounded])
        assert result == [ungrounded]

    def test_missing_frame_refs_key_flagged(self):
        # frame_refs 키 자체가 누락된 경우도 근거 없음으로 본다.
        ungrounded = {"level": "INFO", "message": "정상"}
        result = find_ungrounded_conclusions([ungrounded])
        assert result == [ungrounded]

    def test_punt_language_flagged_even_with_frame_refs(self):
        # frame_refs는 있으나 message가 punt 표현 → 여전히 근거 미흡으로 플래그.
        punt = _grounded(message="ping loss 원인 추가 조사 필요", refs=[9])
        result = find_ungrounded_conclusions([punt])
        assert result == [punt]

    def test_flags_exactly_the_ungrounded_ones(self):
        g1 = _grounded(message="RSSI 최저값 -80dBm", refs=[10])
        g2 = _grounded(message="잦은 로밍: 5회", refs=[11, 12])
        zero_refs = {"level": "WARNING", "message": "Retry 폭증", "frame_refs": []}
        punt = {
            "level": "INFO",
            "message": "further investigation needed",
            "frame_refs": [13],
        }
        output = [g1, zero_refs, g2, punt]
        result = find_ungrounded_conclusions(output)
        # 정확히 근거 없는 두 항목만, 입력 순서대로 반환.
        assert result == [zero_refs, punt]
        assert g1 not in result
        assert g2 not in result

    def test_dict_output_with_conclusions_key(self):
        output = {
            "conclusions": [
                _grounded(refs=[1]),
                {"level": "WARNING", "message": "원인 미상", "frame_refs": [2]},
            ]
        }
        result = find_ungrounded_conclusions(output)
        assert len(result) == 1
        assert result[0]["message"] == "원인 미상"

    def test_empty_and_none_inputs(self):
        assert find_ungrounded_conclusions([]) == []
        assert find_ungrounded_conclusions(None) == []
