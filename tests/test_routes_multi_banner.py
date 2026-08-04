"""분석 페이지 상단 다중 무선 소스 메타 라인 (Jinja 서버 렌더) — 오프셋·병합 요약."""
import json

from fastapi.testclient import TestClient

import config
from app import app

client = TestClient(app)


def _store(tmp_path, monkeypatch, structured):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    result = {
        "id": "multi1", "pcap_name": "w1.pcapng", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": structured, "text_sections": [],
    }
    (tmp_path / "multi1.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8")


def test_multi_wireless_meta_line_shows_offset_and_merge(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, {
        "sources": [
            {"name": "w1.pcapng", "role": "wireless", "frame_count": 100,
             "applied_offset_ms": 0.0, "offset_method": "reference", "warnings": []},
            {"name": "w2.pcapng", "role": "wireless", "frame_count": 98,
             "applied_offset_ms": 183510.0, "offset_method": "tsf", "warnings": []},
        ],
        "merge": {
            "window_ms": 20, "duplicates": 12298, "kept": 186,
            "coverage": {"both": 186, "only": {"w2": 12}},
        },
    })
    html = client.get("/analysis/multi1").text
    assert "무선 소스 2개 병합" in html
    assert "+183.5s" in html
    assert "tsf" in html
    assert "중복 제거" in html
    assert "12,298" in html


def test_single_wireless_no_meta_line(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, {
        "sources": [
            {"name": "w1.pcapng", "role": "wireless", "frame_count": 100, "warnings": []},
        ],
    })
    html = client.get("/analysis/multi1").text
    assert "무선 소스" not in html


def test_old_result_without_merge_key_renders(tmp_path, monkeypatch):
    """구버전 결과(sources는 있지만 merge 키 없음)도 200 렌더, 메타 라인 없음."""
    _store(tmp_path, monkeypatch, {
        "sources": [
            {"name": "w1.pcapng", "role": "wireless", "frame_count": 100, "warnings": []},
            {"name": "w2.pcapng", "role": "wireless", "frame_count": 90, "warnings": []},
        ],
    })
    resp = client.get("/analysis/multi1")
    assert resp.status_code == 200
    # merge 키가 없으면 "중복 제거" 문구는 없어야 하지만, 소스 2개 자체는 메타 라인에 표시될 수 있다.
    assert "중복 제거" not in resp.text


def test_result_without_structured_key_renders(tmp_path, monkeypatch):
    """structured 키 자체가 없는 (더 오래된) 결과도 500을 내지 않는다."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    result = {
        "id": "multi1", "pcap_name": "old.pcapng", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "text_sections": [],
    }
    (tmp_path / "multi1.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8")
    assert client.get("/analysis/multi1").status_code == 200
