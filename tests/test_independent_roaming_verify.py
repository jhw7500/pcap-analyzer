import ast
from collections import OrderedDict
from pathlib import Path
import time

import pytest

from scripts import roaming_independent_verify as verify


def packet(
    *,
    epoch: float,
    subtype: int,
    ta: str,
    ra: str,
    source: str = "primary",
    number: int = 1,
    seq: str = "1",
    retry: bool = False,
) -> verify.PacketEvent:
    return verify.PacketEvent(
        source=source,
        number=number,
        epoch=epoch,
        retry=retry,
        subtype=subtype,
        ta=ta,
        ra=ra,
        bssid=ra,
        seq=seq,
        current_ap="",
        eapol_msg="",
    )


def transaction(*, sta: str, ap: str, epoch: float) -> verify.RoamTransaction:
    return verify.RoamTransaction(
        sta=sta,
        ap=ap,
        auth_epoch=epoch,
        assoc_epoch=epoch + 0.05,
        auth_number=1,
        assoc_number=2,
        auth_basis="auth_request",
        gap_ms=50.0,
        pcap_total_ms=90.0,
    )


def test_verifier_does_not_import_analyzer_package():
    source = Path(verify.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    assert not any(
        name == "analyzer" or name.startswith("analyzer.") for name in imported
    )


def test_estimate_tsf_offsets_uses_common_beacon_median():
    beacons = {
        "primary": {("ap", "1"): 100.0, ("ap", "2"): 101.0},
        "dfk": {("ap", "1"): 282.25, ("ap", "2"): 283.25},
    }

    offsets = verify.estimate_tsf_offsets(beacons, "primary")

    assert offsets["primary"]["offset_sec"] == 0.0
    assert offsets["dfk"]["offset_sec"] == pytest.approx(-182.25)
    assert offsets["dfk"]["pairs"] == 2


def test_cross_source_dedup_keeps_retry_distinction():
    sta, ap = "00:00:00:00:00:01", "00:00:00:00:00:aa"
    primary = packet(epoch=10.0, subtype=2, ta=sta, ra=ap, seq="7")
    copied = packet(
        epoch=192.25,
        subtype=2,
        ta=sta,
        ra=ap,
        source="dfk",
        number=9,
        seq="7",
    )
    retry = packet(
        epoch=192.26,
        subtype=2,
        ta=sta,
        ra=ap,
        source="dfk",
        number=10,
        seq="7",
        retry=True,
    )

    events, duplicates = verify.align_and_dedup(
        {"primary": [primary], "dfk": [copied, retry]},
        {"primary": {"offset_sec": 0}, "dfk": {"offset_sec": -182.25}},
    )

    assert duplicates == 1
    assert len(events) == 2
    assert {event.retry for event in events} == {False, True}
    assert primary.epoch == 10.0
    assert copied.epoch == 192.25


def test_single_association_request_is_a_station_candidate():
    sta, ap = "00:00:00:00:00:01", "00:00:00:00:00:aa"

    candidates = verify.detect_station_macs(
        [packet(epoch=1.0, subtype=2, ta=sta, ra=ap)]
    )

    assert candidates == [sta]


def test_station_candidates_reject_invalid_or_group_addresses():
    ap = "00:00:00:00:00:aa"
    events = [
        packet(epoch=1.0, subtype=0, ta="00:00:00:00:00:00", ra=ap),
        packet(epoch=2.0, subtype=0, ta="01:00:5e:00:00:01", ra=ap),
        packet(epoch=3.0, subtype=0, ta="not-a-mac", ra=ap),
        packet(epoch=4.0, subtype=0, ta="02:00:00:00:00:01", ra=ap),
    ]

    assert verify.detect_station_macs(events) == ["02:00:00:00:00:01"]


def test_packet_ledger_collapses_same_attempt_even_when_retry_arrives_first():
    sta, ap = "00:00:00:00:00:01", "00:00:00:00:00:aa"
    events = [
        packet(epoch=1.0, subtype=11, ta=sta, ra=ap, number=1, seq="1"),
        packet(
            epoch=1.1,
            subtype=2,
            ta=sta,
            ra=ap,
            number=2,
            seq="2",
            retry=True,
        ),
        packet(epoch=1.2, subtype=2, ta=sta, ra=ap, number=3, seq="3"),
        packet(epoch=2.0, subtype=11, ta=sta, ra=ap, number=4, seq="4"),
        packet(epoch=2.1, subtype=2, ta=sta, ra=ap, number=5, seq="5"),
    ]

    rows, meta = verify.build_packet_ledger(events, [sta])

    assert len(rows) == 2
    assert meta["association_repeats_collapsed"] == 1
    assert [row.auth_number for row in rows] == [1, 4]


def test_packet_ledger_does_not_consume_auth_for_another_ap():
    sta = "00:00:00:00:00:01"
    ap1, ap2 = "00:00:00:00:00:a1", "00:00:00:00:00:a2"
    events = [
        packet(epoch=1.0, subtype=11, ta=sta, ra=ap1, number=1),
        packet(epoch=1.1, subtype=2, ta=sta, ra=ap2, number=2),
        packet(epoch=6.0, subtype=2, ta=sta, ra=ap1, number=3),
    ]

    rows, _ = verify.build_packet_ledger(events, [sta])

    assert len(rows) == 2
    assert [row.ap for row in rows] == [ap2, ap1]
    assert all(row.auth_epoch is None for row in rows)
    assert all(row.gap_ms is None for row in rows)


def test_packet_ledger_delayed_retry_preserves_other_ap_auth():
    sta = "00:00:00:00:00:01"
    ap1, ap2 = "00:00:00:00:00:a1", "00:00:00:00:00:a2"
    events = [
        packet(epoch=1.000, subtype=11, ta=sta, ra=ap1, number=1),
        packet(epoch=1.005, subtype=2, ta=sta, ra=ap1, number=2),
        packet(epoch=1.100, subtype=11, ta=sta, ra=ap2, number=3),
        packet(epoch=1.150, subtype=2, ta=sta, ra=ap1, number=4),
        packet(epoch=1.200, subtype=2, ta=sta, ra=ap2, number=5),
    ]

    rows, meta = verify.build_packet_ledger(events, [sta])

    assert meta["association_repeats_collapsed"] == 1
    assert [row.ap for row in rows] == [ap1, ap2]
    assert [row.gap_ms for row in rows] == [5.0, 100.0]


def test_parse_wpa_log_builds_success_and_failure_ledger(tmp_path):
    path = tmp_path / "wpa.log"
    path.write_text(
        "\n".join(
            [
                "2026-07-23 13:00:00.000 Control interface command 'ROAM aa:aa:aa:aa:aa:01'",
                "2026-07-23 13:00:00.123 CTRL-EVENT-CONNECTED - Connection to aa:aa:aa:aa:aa:01 completed",
                "2026-07-23 13:01:00.000 Control interface command 'ROAM aa:aa:aa:aa:aa:02'",
                "2026-07-23 13:01:01.000 CTRL-EVENT-ASSOC-REJECT status_code=1",
            ]
        ),
        encoding="utf-8",
    )

    rows = verify.parse_wpa_log(path, "1호기")

    assert len(rows) == 2
    assert rows[0].total_ms == pytest.approx(123.0)
    assert rows[0].failed is False
    assert rows[1].failed is True
    assert rows[1].fail_reason == "CTRL-EVENT-ASSOC-REJECT"


def test_parse_wpa_log_streams_instead_of_reading_whole_file(tmp_path, monkeypatch):
    path = tmp_path / "wpa.log"
    path.write_text(
        "2026-07-23 13:00:00.000 Control interface command "
        "'ROAM aa:aa:aa:aa:aa:01'\n"
        "2026-07-23 13:00:00.100 CTRL-EVENT-CONNECTED - Connection to "
        "aa:aa:aa:aa:aa:01 completed\n",
        encoding="utf-8",
    )

    def reject_read_text(*_args, **_kwargs):
        raise AssertionError("wpa.log 전체 읽기 금지")

    monkeypatch.setattr(Path, "read_text", reject_read_text)

    rows = verify.parse_wpa_log(path, "1호기")

    assert len(rows) == 1
    assert rows[0].total_ms == 100.0


def test_station_timestamp_timezone_is_host_independent():
    tz = verify._parse_utc_offset("+09:00")

    assert verify._parse_local_epoch("1970-01-01 09:00:00.000", tz) == 0.0
    with pytest.raises(ValueError, match="UTC offset"):
        verify._parse_utc_offset("KST")


def test_station_timestamp_accepts_seconds_and_microseconds():
    tz = verify._parse_utc_offset("+09:00")

    whole = verify._parse_local_epoch("2026-01-01 09:00:00", tz)
    micros = verify._parse_local_epoch("2026-01-01 09:00:00.123456", tz)

    assert micros - whole == pytest.approx(0.123456)


def test_auto_binding_and_correlation_are_one_to_one():
    sta1, sta2 = "00:00:00:00:00:01", "00:00:00:00:00:02"
    ap1, ap2 = "00:00:00:00:00:a1", "00:00:00:00:00:a2"
    packets = [
        transaction(sta=sta1, ap=ap1, epoch=102.0),
        transaction(sta=sta1, ap=ap1, epoch=202.0),
        transaction(sta=sta2, ap=ap2, epoch=302.0),
        transaction(sta=sta2, ap=ap2, epoch=402.0),
    ]
    logs = {
        "one": [
            verify.StationRoam("one", 1, ap1, 100.0, 100.1, 100.0, False, ""),
            verify.StationRoam("one", 2, ap1, 200.0, 200.1, 100.0, False, ""),
        ],
        "two": [
            verify.StationRoam("two", 1, ap2, 300.0, 300.1, 100.0, False, ""),
            verify.StationRoam("two", 2, ap2, 400.0, 400.1, 100.0, False, ""),
        ],
    }

    bindings, _ = verify.bind_stations(logs, packets)
    correlation = verify.correlate_station_logs(logs, packets, bindings)

    assert bindings["one"].sta == sta1
    assert bindings["two"].sta == sta2
    assert bindings["one"].offset_sec == pytest.approx(2.0)
    assert correlation["matched"] == 4
    assert not correlation["unmatched_station_success"]
    assert not correlation["unmatched_packets"]


def test_auth_missing_transaction_uses_assoc_epoch_for_station_matching():
    sta, ap = "00:00:00:00:00:01", "00:00:00:00:00:a1"
    packet_roam = verify.RoamTransaction(
        sta=sta,
        ap=ap,
        auth_epoch=None,
        assoc_epoch=102.0,
        auth_number=None,
        assoc_number=2,
        auth_basis=None,
        gap_ms=None,
        pcap_total_ms=None,
    )
    logs = {
        "one": [
            verify.StationRoam(
                "one", 1, ap, 100.0, 100.11, 110.0, False, ""
            )
        ]
    }

    bindings, _ = verify.bind_stations(logs, [packet_roam])
    correlation = verify.correlate_station_logs(
        logs, [packet_roam], bindings
    )

    assert bindings["one"].sta == sta
    assert bindings["one"].matched == 1
    assert bindings["one"].offset_sec == pytest.approx(2.0)
    assert correlation["matched"] == 1
    assert packet_roam.sta_source == "one"
    assert packet_roam.sta_total_ms == 110.0
    assert not correlation["unmatched_station_success"]
    assert not correlation["unmatched_packets"]


def test_station_binding_learns_large_clock_offset():
    sta, ap = "00:00:00:00:00:01", "00:00:00:00:00:a1"
    packets = [
        transaction(sta=sta, ap=ap, epoch=3700.0),
        transaction(sta=sta, ap=ap, epoch=3800.0),
    ]
    logs = [
        verify.StationRoam("one", 1, ap, 100.0, 100.1, 100.0, False, ""),
        verify.StationRoam("one", 2, ap, 200.0, 200.1, 100.0, False, ""),
    ]

    score = verify.score_station_binding("one", logs, sta, packets)

    assert score.matched == 2
    assert score.offset_sec == pytest.approx(3600.0)


def test_hungarian_assignment_scales_and_finds_unique_optimum():
    size = 12
    weights = [
        [100.0 if row == col else 0.0 for col in range(size)] for row in range(size)
    ]

    assert verify._maximum_weight_assignment(weights) == list(range(size))


def test_tshark_rows_drains_large_stderr_without_deadlock(tmp_path):
    fake = tmp_path / "fake-tshark"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('x' * 200000)\n"
        "print('1')\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"x")

    rows = list(verify._tshark_rows([pcap], ("field",), "", str(fake)))

    assert rows == [(pcap, ["1"])]


def test_tshark_rows_terminates_process_on_cancel(tmp_path):
    fake = tmp_path / "slow-tshark"
    fake.write_text(
        "#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"x")
    started = time.monotonic()

    with pytest.raises(verify.VerificationCancelled):
        list(
            verify._tshark_rows(
                [pcap],
                ("field",),
                "",
                str(fake),
                cancelled=lambda: time.monotonic() - started > 0.2,
            )
        )

    assert time.monotonic() - started < 3.0


def test_packet_event_limit_is_global_across_sources(monkeypatch, tmp_path):
    paths = [tmp_path / "one.pcap", tmp_path / "two.pcap"]
    sources = OrderedDict((f"w{index}", [path]) for index, path in enumerate(paths, 1))

    def rows(input_paths, *_args, **_kwargs):
        for path in input_paths:
            for number in range(2):
                yield path, [
                    str(number + 1),
                    str(100 + number),
                    "0",
                    "2",
                    "00:00:00:00:00:01",
                    "00:00:00:00:00:aa",
                    "00:00:00:00:00:aa",
                    str(number),
                    "",
                    "",
                ]

    monkeypatch.setattr(verify, "_tshark_rows", rows)

    with pytest.raises(RuntimeError, match=r"상한\(3건\) 초과"):
        verify.extract_packet_events(sources, max_rows=3)


def test_beacon_limit_counts_unique_keys_globally(monkeypatch, tmp_path):
    paths = [tmp_path / "one.pcap", tmp_path / "two.pcap"]
    sources = OrderedDict((f"w{index}", [path]) for index, path in enumerate(paths, 1))

    def rows(input_paths, *_args, **_kwargs):
        for path in input_paths:
            yield path, ["100.0", "00:00:00:00:00:aa", path.stem]

    monkeypatch.setattr(verify, "_tshark_rows", rows)

    with pytest.raises(RuntimeError, match=r"Beacon 키 상한\(1건\) 초과"):
        verify.extract_beacons(sources, max_keys=1)


def test_explicit_binding_must_cover_every_station():
    rows = [transaction(sta="sta-1", ap="ap-1", epoch=1.0)]
    logs = {
        "one": [verify.StationRoam("one", 1, "ap-1", 1.0, 1.1, 100, False, "")],
        "two": [],
    }

    with pytest.raises(ValueError, match="missing_station"):
        verify.bind_stations(logs, rows, explicit={"one": "sta-1"})


def test_compact_analyzer_summary_can_be_compared_without_internal_schema():
    rows = [transaction(sta="sta", ap="ap", epoch=1.0)]
    rows[0].sta_total_ms = 200.0
    verify.classify_transactions(rows)
    analyzer_result = {
        "roaming_total": 1,
        "slow": 1,
        "decided": 1,
        "unmeasured": 0,
        "sta_attached": 1,
    }

    comparison = verify.compare_analyzer(analyzer_result, rows, sta_attached=1)

    assert comparison["clean"] is True
    assert comparison["summary_diff"] == {}


def test_detailed_comparison_detects_analyzer_only_event():
    rows = [transaction(sta="sta", ap="ap", epoch=1.0)]
    verify.classify_transactions(rows)
    analyzer_result = {
        "structured": {
            "roaming": {
                "sequences": [
                    {
                        "sta": "sta",
                        "ap": "ap",
                        "auth_epoch": 1.0,
                        "is_slow": False,
                        "slow_basis": "total",
                    },
                    {
                        "sta": "sta",
                        "ap": "ap",
                        "auth_epoch": 2.0,
                        "is_slow": False,
                        "slow_basis": "total",
                    },
                ]
            },
            "station_logs": {"stations": [{"attached": 1}]},
        }
    }

    comparison = verify.compare_analyzer(analyzer_result, rows, sta_attached=1)

    assert comparison["clean"] is False
    assert comparison["summary_diff"]["roaming_total"] == {
        "analyzer": 2,
        "independent": 1,
    }
    assert len(comparison["event_diff"]["analyzer_only"]) == 1
    assert comparison["event_diff"]["independent_only"] == []
