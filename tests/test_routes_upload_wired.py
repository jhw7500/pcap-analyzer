"""POST /api/upload의 wired_file 처리."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20  # little-endian pcap


def _ok_result(pcap_path, **kwargs):
    return {
        "id": "t1", "pcap_name": "x", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": {"sources": [
            {"name": "tmpA", "role": "wireless", "frame_count": 1, "warnings": []},
            {"name": "tmpB", "role": "wired", "frame_count": None, "warnings": []},
        ]},
        "text_sections": [],
    }


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_wired_file_passed_to_pipeline(mock_run, _tshark, tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
        "wired_file": ("cable.pcapng", PCAP_MAGIC, "application/octet-stream"),
    })
    assert resp.status_code == 200
    assert mock_run.call_args.kwargs["wired_path"]  # 임시 경로가 전달됨
    saved = (tmp_path / "t1.json").read_text(encoding="utf-8")
    assert "cable.pcapng" in saved and '"pcap_names"' in saved


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_without_wired_file_wired_path_empty(mock_run, _tshark, tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
    })
    assert resp.status_code == 200
    assert mock_run.call_args.kwargs["wired_path"] == ""


@patch("routes.upload.config.detect_tshark", return_value="tshark")
def test_wired_file_invalid_magic_rejected(_tshark):
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
        "wired_file": ("bad.pcapng", b"NOTPCAP" + b"\x00" * 20, "application/octet-stream"),
    })
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_MAGIC"
