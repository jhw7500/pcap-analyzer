"""라우트 추가 테스트 — 분석 결과가 있는 시나리오."""

import json
from pathlib import Path
from fastapi.testclient import TestClient

from app import app
import config

client = TestClient(app)


def _create_fake_analysis(with_timeout: bool = True):
    """임시 분석 결과 JSON을 생성하고 ID를 반환."""
    data_dir = config.ensure_data_dir()
    fake_id = "test_fake_12345"
    result = {
        "id": fake_id,
        "pcap_name": "test.pcap",
        "pcap_size": 1024,
        "frame_count": 100,
        "analyzed_at": "2026-01-01 00:00:00",
        "structured": {
            "overview": {"total_frames": 100, "retry_pct": 5, "devices": []},
            "signal": {"stas": {}},
            "ping": {
                "full_list": [
                    {
                        "seq": "1",
                        "status": "matched",
                        "epoch": 1000.0,
                        "rtt_ms": 5.0,
                        "req_num": 10,
                        "req_time": "00:00:01.000",
                        "reply_num": 11,
                        "reply_time": "00:00:01.005",
                        "src": "10.0.0.1",
                        "dst": "10.0.0.2",
                        "src_mac": "STA1(0002)",
                        "dst_mac": "AP1(0001)",
                        "has_retry": False,
                        "req_rssi": -55,
                    },
                    {
                        "seq": "2",
                        "status": "loss",
                        "epoch": 1001.0,
                        "rtt_ms": None,
                        "req_num": 12,
                        "req_time": "00:00:02.000",
                        "reply_num": None,
                        "reply_time": None,
                        "src": "10.0.0.1",
                        "dst": "10.0.0.2",
                        "src_mac": "STA1(0002)",
                        "dst_mac": "AP1(0001)",
                        "has_retry": False,
                        "req_rssi": -60,
                    },
                ]
                if with_timeout
                else [],
                "pairs": [
                    {
                        "seq": "1",
                        "status": "matched",
                        "epoch": 1000.0,
                        "rtt_ms": 5.0,
                        "req_num": 10,
                        "req_time": "00:00:01.000",
                        "reply_num": 11,
                        "reply_time": "00:00:01.005",
                        "src": "10.0.0.1",
                        "dst": "10.0.0.2",
                        "src_mac": "STA1(0002)",
                        "dst_mac": "AP1(0001)",
                        "has_retry": False,
                        "req_rssi": -55,
                    }
                ]
                if with_timeout
                else [],
                "losses": [
                    {
                        "seq": "2",
                        "status": "loss",
                        "epoch": 1001.0,
                        "rtt_ms": None,
                        "req_num": 12,
                        "req_time": "00:00:02.000",
                        "reply_num": None,
                        "reply_time": None,
                        "src": "10.0.0.1",
                        "dst": "10.0.0.2",
                        "src_mac": "STA1(0002)",
                        "dst_mac": "AP1(0001)",
                        "has_retry": False,
                        "req_rssi": -60,
                    }
                ]
                if with_timeout
                else [],
                "stats": {
                    "count": 1,
                    "min": 5.0,
                    "max": 5.0,
                    "avg": 5.0,
                    "p50": 5.0,
                    "p95": 5.0,
                    "p99": 5.0,
                    "loss_count": 1,
                    "loss_pct": 50.0,
                }
                if with_timeout
                else {},
            },
            "roaming": {"sequences": []},
            "per_second": {"timeline": []},
            "device_stats": {},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
            "diagnosis": {
                "health": {"score": 80, "grade": "양호", "color": "green"},
                "issues": [],
                "sta_diags": [],
                "component_scores": {},
                "summary": {},
            },
        },
        "text_sections": [
            {"title": "1. 개요", "lines": ["100프레임"], "summary": "100프레임"},
        ],
    }
    path = data_dir / f"{fake_id}.json"
    path.write_text(json.dumps(result, ensure_ascii=False))
    return fake_id, path


class TestAnalysisWithData:
    def test_analysis_page(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get(f"/analysis/{fake_id}")
            assert resp.status_code == 200
            assert "test.pcap" in resp.text
            assert "Casefile 보기" in resp.text
            assert f"/analysis/{fake_id}/casefile" in resp.text
        finally:
            path.unlink(missing_ok=True)

    def test_api_json(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get(f"/api/analysis/{fake_id}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["frame_count"] == 100
        finally:
            path.unlink(missing_ok=True)

    def test_api_text(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get(f"/api/analysis/{fake_id}/text")
            assert resp.status_code == 200
            assert "100프레임" in resp.text
        finally:
            path.unlink(missing_ok=True)

    def test_delete(self):
        fake_id, path = _create_fake_analysis()
        resp = client.delete(f"/api/analysis/{fake_id}")
        assert resp.status_code == 200
        assert not path.exists()

    def test_api_casefile_json(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get(f"/api/analysis/{fake_id}/casefile")
            assert resp.status_code == 200
            data = resp.json()
            assert data["schema_version"] == "1.0"
            assert data["analysis_id"] == fake_id
            assert data["incident_id"].startswith(f"{fake_id}:")
            assert "ping" in data
            assert "layers" in data
        finally:
            path.unlink(missing_ok=True)

    def test_api_casefile_text(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get(f"/api/analysis/{fake_id}/casefile/text")
            assert resp.status_code == 200
            assert fake_id in resp.text
        finally:
            path.unlink(missing_ok=True)

    def test_api_casefile_invalid_incident(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get(
                f"/api/analysis/{fake_id}/casefile?incident_id=bad-incident"
            )
            assert resp.status_code == 404
            assert resp.json()["code"] == "INCIDENT_NOT_FOUND"
        finally:
            path.unlink(missing_ok=True)

    def test_api_casefile_unavailable_without_timeout(self):
        fake_id, path = _create_fake_analysis(with_timeout=False)
        try:
            resp = client.get(f"/api/analysis/{fake_id}/casefile")
            assert resp.status_code == 422
            assert resp.json()["code"] == "CASEFILE_UNAVAILABLE"
        finally:
            path.unlink(missing_ok=True)

    def test_index_lists_analyses(self):
        fake_id, path = _create_fake_analysis()
        try:
            resp = client.get("/")
            assert resp.status_code == 200
            assert "test.pcap" in resp.text
        finally:
            path.unlink(missing_ok=True)


class TestSettingsPost:
    def test_save_settings(self):
        resp = client.post(
            "/settings",
            data={
                "tshark_path": "",
                "ai_provider": "claude",
                "ai_api_key": "",
                "ai_model": "claude-sonnet-4-6",
                "ai_auto_review": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
