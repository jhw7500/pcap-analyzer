"""POST /api/upload의 wired_file 처리."""
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import app
from routes import upload as upload_module

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


@patch("routes.upload.config.detect_tshark", return_value="tshark")
def test_wired_save_exception_cleans_up_primary_tmp(_tshark):
    """유선 저장이 (제어된 에러가 아니라) 예외를 던지면 무선 임시파일도 정리돼야 한다."""
    original_save = upload_module._save_pcap_upload
    captured = {}
    call_count = {"n": 0}

    async def fake_save(file, budget=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # 무선(첫 번째) 호출은 실제 헬퍼로 위임해 실제 tmp 경로를 확보
            tmp_name, err = await original_save(file, budget)
            captured["primary_tmp"] = tmp_name
            return tmp_name, err
        raise RuntimeError("wired 저장 중 I/O 예외 시뮬레이션")

    with patch("routes.upload._save_pcap_upload", side_effect=fake_save):
        with pytest.raises(RuntimeError):
            client.post("/api/upload", files={
                "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
                "wired_file": ("cable.pcapng", PCAP_MAGIC, "application/octet-stream"),
            })

    assert captured.get("primary_tmp")
    assert not Path(captured["primary_tmp"]).exists()


@patch("routes.upload.config.detect_tshark", return_value="tshark")
def test_job_registration_exception_cleans_up_both_tmp(_tshark):
    """wired 저장까지 성공한 뒤(두 tmp 모두 디스크에 존재) job 등록 단계
    (_jobs_lock 진입~_prune_jobs_locked)에서 예외가 나면, 아직 실행 try/finally에
    진입하지 못했으므로 별도 가드가 없으면 두 tmp 모두 정리되지 않는다
    (PR #22 10라운드 — Finding E)."""
    original_save = upload_module._save_pcap_upload
    captured = {}
    call_count = {"n": 0}

    async def capturing_save(file, budget=None):
        call_count["n"] += 1
        tmp_name, err = await original_save(file, budget)
        captured["primary_tmp" if call_count["n"] == 1 else "wired_tmp"] = tmp_name
        return tmp_name, err

    with patch("routes.upload._save_pcap_upload", side_effect=capturing_save), \
         patch("routes.upload._prune_jobs_locked",
               side_effect=RuntimeError("job 등록 중 예외 시뮬레이션")):
        with pytest.raises(RuntimeError):
            client.post("/api/upload", files={
                "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
                "wired_file": ("cable.pcapng", PCAP_MAGIC, "application/octet-stream"),
            })

    assert captured.get("primary_tmp") and captured.get("wired_tmp")
    assert not Path(captured["primary_tmp"]).exists()
    assert not Path(captured["wired_tmp"]).exists()
