"""POST /api/upload의 wireless_files(다중 무선) 처리."""
import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app
from routes import upload as upload_module

client = TestClient(app)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20  # little-endian pcap
BAD_MAGIC = b"NOTPCAP" + b"\x00" * 20


def _ok_result(pcap_path, **kwargs):
    """무선 sources 개수를 wireless_paths kwarg 길이에 맞춰 동적으로 구성."""
    wireless_paths = kwargs.get("wireless_paths") or []
    total_wireless = 1 + len(wireless_paths)
    sources = [
        {"name": f"tmpW{i}", "role": "wireless", "frame_count": 1, "warnings": []}
        for i in range(total_wireless)
    ]
    return {
        "id": "t1", "pcap_name": "x", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": {"sources": sources},
        "text_sections": [],
    }


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_wireless_files_passed_to_pipeline(mock_run, _tshark, tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files=[
        ("file", ("w1.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("w2.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("w3.pcapng", PCAP_MAGIC, "application/octet-stream")),
    ])
    assert resp.status_code == 200
    assert len(mock_run.call_args.kwargs["wireless_paths"]) == 2


@patch("routes.upload.config.detect_tshark", return_value="tshark")
def test_wireless_files_over_limit_rejected(_tshark):
    """file(1) + wireless_files(4) = 총 5개 → 상한(4) 초과로 400."""
    resp = client.post("/api/upload", files=[
        ("file", ("w1.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("w2.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("w3.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("w4.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("w5.pcapng", PCAP_MAGIC, "application/octet-stream")),
    ])
    assert resp.status_code == 400
    assert resp.json()["code"] == "TOO_MANY_FILES"


@patch("routes.upload.config.detect_tshark", return_value="tshark")
def test_wireless_bad_magic_cleans_up_prior_tmps(_tshark):
    """wireless_files 중 하나가 magic 불량이면 그 이전에 저장된 tmp(주 파일 +
    앞선 wireless 파일들)를 전부 정리해야 한다."""
    original_save = upload_module._save_pcap_upload
    captured = []

    async def capturing_save(file):
        tmp_name, err = await original_save(file)
        if tmp_name:
            captured.append(tmp_name)
        return tmp_name, err

    with patch("routes.upload._save_pcap_upload", side_effect=capturing_save):
        resp = client.post("/api/upload", files=[
            ("file", ("w1.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ("wireless_files", ("w2.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ("wireless_files", ("bad.pcapng", BAD_MAGIC, "application/octet-stream")),
        ])

    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_MAGIC"
    assert len(captured) == 2  # 주 파일 + 첫 wireless(성공)만 tmp 생성됨
    for p in captured:
        assert not Path(p).exists()


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_no_wireless_files_wireless_paths_empty(mock_run, _tshark, tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
    })
    assert resp.status_code == 200
    assert mock_run.call_args.kwargs["wireless_paths"] == []


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_wireless_names_substituted_in_order(mock_run, _tshark, tmp_path, monkeypatch):
    """다중 무선 sources의 임시파일명을 업로드 순서대로 원본 파일명으로 치환."""
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files=[
        ("file", ("primary.pcapng", PCAP_MAGIC, "application/octet-stream")),
        ("wireless_files", ("second.pcapng", PCAP_MAGIC, "application/octet-stream")),
    ])
    assert resp.status_code == 200
    saved = json.loads((tmp_path / "t1.json").read_text(encoding="utf-8"))
    names = [s["name"] for s in saved["structured"]["sources"] if s["role"] == "wireless"]
    assert names == ["primary.pcapng", "second.pcapng"]
    assert saved["pcap_names"] == ["primary.pcapng", "second.pcapng"]
