"""9번 로밍 영향 분석이 canonical pairing과 같은 이벤트를 쓰는지 검증."""

import inspect

from tests.conftest import AP1, STA1, make_frame

from analyzer.core.modules import roaming_impact
from analyzer.core.modules.roaming import pair_roaming_sequences


ROLES = {
    STA1: {"role": "STA", "name": "STA1"},
    AP1: {"role": "AP", "name": "AP1"},
}


def _auth(number, epoch):
    return make_frame(number=number, epoch=epoch, subtype="11", ta=STA1, ra=AP1)


def _reassoc(number, epoch, *, retry=False):
    return make_frame(
        number=number, epoch=epoch, subtype="2", ta=STA1, ra=AP1, retry=retry
    )


def test_impact_count_matches_canonical_pairing_with_reassoc_retries():
    frames = [
        _auth(1, 1000.000),
        _reassoc(2, 1000.005, retry=True),
        _reassoc(3, 1000.009),       # 스니퍼 순서 역전 사본
        _reassoc(4, 1000.159),       # 같은 로밍의 새-seq association 재시도
        _auth(5, 1010.000),
        _reassoc(6, 1010.006),
    ]
    expected = pair_roaming_sequences(frames, {STA1})
    events = roaming_impact._find_roaming_events(frames, ROLES)

    assert len(expected) == len(events) == 2
    assert [event["assoc_frame"].number for event in events] == [2, 6]
    section = roaming_impact.analyze(frames, ROLES)
    assert section.summary.startswith("로밍 2건")
    assert section.lines[0].startswith("총 2건")


def test_impact_keeps_genuinely_unmeasurable_roam_and_renders_safely():
    frames = [_reassoc(1, 1000.000)]
    events = roaming_impact._find_roaming_events(frames, ROLES)
    assert len(events) == 1
    assert events[0]["auth_frame"] is None
    assert events[0]["handshake_ms"] is None

    section = roaming_impact.analyze(frames, ROLES)
    assert "Auth 미포착" in "\n".join(section.lines)
    assert section.summary.startswith("로밍 1건")


def test_impact_detection_rule_is_not_reimplemented():
    """독자 Auth 맵을 되살리면 4번/9번 로밍 건수가 다시 갈라진다."""
    source = inspect.getsource(roaming_impact._find_roaming_events)
    assert "pair_roaming_sequences" in source
    assert "auth_by_sta" not in source
