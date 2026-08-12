import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import config
from app import app
from routes import analysis as analysis_module
from routes import independent_validation as validation_module
from routes.independent_validation import (
    IndependentValidationCancelled,
    failed_validation_payload,
    run_independent_web_validation,
)


client = TestClient(app)
PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 32


def validation_report(clean=True):
    return {
        "schema": "independent_roaming_verifier_v1",
        "inputs": {"sources": {}, "stations": {}, "station_utc_offset": "+09:00"},
        "packet": {"roaming_total": 2, "slow": 1, "decided": 2, "unmeasured": 0},
        "station_logs": {
            "commands": 2,
            "success": 2,
            "failed": 0,
            "matched": 2,
            "total_ms": {"p50": 111.0, "p95": 139.0},
            "by_station": {"1호기": {"path": "/tmp/private-wpa.log"}},
        },
        "bindings": {},
        "analyzer_comparison": {"clean": clean, "summary_diff": {}},
        "transactions": [],
        "elapsed_sec": 1.25,
    }


def analyzer_result(analysis_id="web-validation-test"):
    return {
        "id": analysis_id,
        "pcap_name": "test.pcap",
        "frame_count": 10,
        "analyzed_at": "2026-08-12 12:00:00",
        "structured": {"sources": [{"name": "tmp", "role": "wireless"}]},
        "text_sections": [],
    }


def test_web_wrapper_scrubs_temporary_paths_and_marks_complete(tmp_path):
    primary = tmp_path / "secret-primary.pcap"
    secondary = tmp_path / "secret-secondary.pcap"
    wpa = tmp_path / "secret-wpa.log"
    for path in (primary, secondary, wpa):
        path.write_text("x", encoding="utf-8")

    with patch(
        "routes.independent_validation.run_verification",
        return_value=validation_report(),
    ) as verifier:
        report = run_independent_web_validation(
            str(primary),
            [str(secondary)],
            [{"name": "1호기", "files": {"wpa.log": str(wpa)}}],
            analyzer_result(),
            tshark="tshark",
            source_names=["primary.pcap", "dfk.pcap"],
        )

    assert report["status"] == "complete"
    assert report["inputs"]["sources"] == {
        "w1": ["primary.pcap"],
        "w2": ["dfk.pcap"],
    }
    assert report["inputs"]["stations"] == {"1호기": "1호기/wpa.log"}
    assert str(tmp_path) not in json.dumps(report, ensure_ascii=False)
    assert "/tmp/private-wpa.log" not in json.dumps(report, ensure_ascii=False)
    assert report["station_logs"]["by_station"]["1호기"]["path"] == "1호기/wpa.log"
    assert verifier.call_args.kwargs["analyzer_result"]["id"] == "web-validation-test"


def test_web_wrapper_honors_cancel_before_work(tmp_path):
    primary = tmp_path / "x.pcap"
    primary.write_bytes(PCAP)

    def fake_verifier(*_args, progress_cb, **_kwargs):
        progress_cb("start", 1)

    with patch(
        "routes.independent_validation.run_verification", side_effect=fake_verifier
    ):
        with pytest.raises(IndependentValidationCancelled):
            run_independent_web_validation(
                str(primary),
                [],
                [],
                analyzer_result(),
                tshark="tshark",
                source_names=["x.pcap"],
                cancelled=lambda: True,
            )


def test_web_wrapper_can_cancel_while_waiting_for_memory_slot(tmp_path):
    primary = tmp_path / "x.pcap"
    primary.write_bytes(PCAP)
    checks = iter([False, True])

    assert validation_module._verification_slot.acquire(timeout=0)
    try:
        with patch("routes.independent_validation.run_verification") as verifier:
            with pytest.raises(IndependentValidationCancelled):
                run_independent_web_validation(
                    str(primary),
                    [],
                    [],
                    analyzer_result(),
                    tshark="tshark",
                    source_names=["x.pcap"],
                    cancelled=lambda: next(checks, True),
                )
        verifier.assert_not_called()
    finally:
        validation_module._verification_slot.release()


def test_web_wrapper_rejects_duplicate_station_names(tmp_path):
    primary = tmp_path / "x.pcap"
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    primary.write_bytes(PCAP)
    first.write_text("x")
    second.write_text("x")

    with pytest.raises(ValueError, match="중복된 STA 로그 이름"):
        run_independent_web_validation(
            str(primary),
            [],
            [
                {"name": "same", "files": {"wpa.log": str(first)}},
                {"name": "same", "files": {"wpa.log": str(second)}},
            ],
            analyzer_result(),
            tshark="tshark",
            source_names=["x.pcap"],
        )


def test_failed_payload_hides_temporary_paths():
    payload = failed_validation_payload(
        RuntimeError("tshark failed: /tmp/private-capture.pcap"),
        ["/tmp/private-capture.pcap"],
    )

    assert payload["status"] == "failed"
    assert "/tmp/private" not in payload["error"]
    assert "<업로드 파일>" in payload["error"]


def test_upload_opt_in_runs_verifier_and_persists_report(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    result = analyzer_result("web-opt-in")
    report = {**validation_report(), "status": "complete"}
    with (
        patch("routes.upload.config.detect_tshark", return_value="tshark"),
        patch("routes.upload.run_analysis", return_value=result),
        patch(
            "routes.upload.run_independent_web_validation", return_value=report
        ) as verifier,
    ):
        response = client.post(
            "/api/upload",
            files={"file": ("primary.pcap", PCAP, "application/octet-stream")},
            data={"independent_validation": "true"},
        )

    assert response.status_code == 200
    saved = json.loads((tmp_path / "web-opt-in.json").read_text(encoding="utf-8"))
    assert saved["independent_validation"]["status"] == "complete"
    assert verifier.call_count == 1


def test_upload_default_does_not_run_verifier(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    with (
        patch("routes.upload.config.detect_tshark", return_value="tshark"),
        patch(
            "routes.upload.run_analysis", return_value=analyzer_result("web-default")
        ),
        patch("routes.upload.run_independent_web_validation") as verifier,
    ):
        response = client.post(
            "/api/upload",
            files={"file": ("primary.pcap", PCAP, "application/octet-stream")},
        )

    assert response.status_code == 200
    verifier.assert_not_called()


def test_upload_rejects_filtered_independent_validation_before_saving():
    with patch("routes.upload.config.detect_tshark", return_value="tshark"):
        response = client.post(
            "/api/upload",
            files={"file": ("primary.pcap", PCAP, "application/octet-stream")},
            data={"independent_validation": "true", "time_start": "2026-01-01"},
        )

    assert response.status_code == 400
    assert response.json()["code"] == "INDEPENDENT_VALIDATION_FILTERED"


def test_upload_validation_failure_preserves_main_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    with (
        patch("routes.upload.config.detect_tshark", return_value="tshark"),
        patch(
            "routes.upload.run_analysis",
            return_value=analyzer_result("web-validation-failed"),
        ),
        patch(
            "routes.upload.run_independent_web_validation",
            side_effect=RuntimeError("common TSF missing"),
        ),
    ):
        response = client.post(
            "/api/upload",
            files={"file": ("primary.pcap", PCAP, "application/octet-stream")},
            data={"independent_validation": "true"},
        )

    assert response.status_code == 200
    saved = json.loads(
        (tmp_path / "web-validation-failed.json").read_text(encoding="utf-8")
    )
    assert saved["id"] == "web-validation-failed"
    assert saved["independent_validation"]["status"] == "failed"


def test_upload_unexpected_validation_error_preserves_main_analysis(
    tmp_path, monkeypatch
):
    """교차검증 구현 결함도 이미 완료된 본 분석을 폐기하면 안 된다."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    with (
        patch("routes.upload.config.detect_tshark", return_value="tshark"),
        patch(
            "routes.upload.run_analysis",
            return_value=analyzer_result("web-validation-unexpected"),
        ),
        patch(
            "routes.upload.run_independent_web_validation",
            side_effect=KeyError("unexpected schema"),
        ),
    ):
        response = client.post(
            "/api/upload",
            files={"file": ("primary.pcap", PCAP, "application/octet-stream")},
            data={"independent_validation": "true"},
        )

    assert response.status_code == 200
    saved = json.loads(
        (tmp_path / "web-validation-unexpected.json").read_text(encoding="utf-8")
    )
    assert saved["id"] == "web-validation-unexpected"
    assert saved["independent_validation"]["status"] == "failed"
    assert "unexpected schema" in saved["independent_validation"]["error"]


def test_validation_routes_and_analysis_panel(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    analysis_module._invalidate_result_cache()
    result = analyzer_result("web-panel")
    result["independent_validation"] = {
        **validation_report(),
        "status": "complete",
    }
    (tmp_path / "web-panel.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8"
    )

    page = client.get("/analysis/web-panel")
    data = client.get("/api/analysis/web-panel/independent-validation")
    markdown = client.get("/api/analysis/web-panel/independent-validation.md")

    assert page.status_code == 200
    assert "독립 로밍 교차검증 — 분석기와 일치" in page.text
    assert data.status_code == 200
    assert data.json()["packet"]["roaming_total"] == 2
    assert markdown.status_code == 200
    assert "# 독립 로밍 검증 보고서" in markdown.text


def test_analysis_panel_uses_dash_when_station_percentiles_are_missing(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    analysis_module._invalidate_result_cache()
    result = analyzer_result("web-no-station-percentiles")
    report = validation_report()
    report["station_logs"]["total_ms"]["p50"] = None
    report["station_logs"]["total_ms"]["p95"] = None
    result["independent_validation"] = {**report, "status": "complete"}
    (tmp_path / "web-no-station-percentiles.json").write_text(
        json.dumps(result), encoding="utf-8"
    )

    page = client.get("/analysis/web-no-station-percentiles")

    assert page.status_code == 200
    assert "Nonems" not in page.text


def test_validation_route_reports_not_requested(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    analysis_module._invalidate_result_cache()
    (tmp_path / "without-validation.json").write_text(
        json.dumps(analyzer_result("without-validation")), encoding="utf-8"
    )

    response = client.get("/api/analysis/without-validation/independent-validation")

    assert response.status_code == 404
    assert response.json()["code"] == "INDEPENDENT_VALIDATION_NOT_FOUND"


def test_analysis_panel_renders_mismatch_details(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    analysis_module._invalidate_result_cache()
    result = analyzer_result("web-mismatch")
    report = validation_report(clean=False)
    report["analyzer_comparison"]["summary_diff"] = {
        "roaming_total": {"analyzer": 3, "independent": 2}
    }
    result["independent_validation"] = {**report, "status": "complete"}
    (tmp_path / "web-mismatch.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8"
    )

    page = client.get("/analysis/web-mismatch")

    assert page.status_code == 200
    assert "독립 로밍 교차검증 — 차이 발견" in page.text
    assert "roaming_total" in page.text


def test_failed_validation_markdown_returns_422(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    analysis_module._invalidate_result_cache()
    result = analyzer_result("web-failed-download")
    result["independent_validation"] = {
        "status": "failed",
        "error": "TSF missing",
    }
    (tmp_path / "web-failed-download.json").write_text(
        json.dumps(result), encoding="utf-8"
    )

    response = client.get("/api/analysis/web-failed-download/independent-validation.md")

    assert response.status_code == 422
    assert response.json()["code"] == "INDEPENDENT_VALIDATION_FAILED"
