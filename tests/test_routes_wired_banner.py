"""분석 페이지 상단 입력 파일 경고 배너 (Jinja 서버 렌더)."""
import json

from fastapi.testclient import TestClient

import config
from app import app

client = TestClient(app)


def _store(tmp_path, monkeypatch, sources):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    result = {
        "id": "warn1", "pcap_name": "w.pcapng", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": {"sources": sources}, "text_sections": [],
    }
    (tmp_path / "warn1.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8")


def test_banner_shown_when_source_has_warning(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, [
        {"name": "cable.pcapng", "role": "wired", "frame_count": None,
         "warnings": ["무선(802.11) 캡처다 — 유선 캡처를 넣어라: x"]},
    ])
    html = client.get("/analysis/warn1").text
    assert "입력 파일 경고" in html and "cable.pcapng" in html


def test_no_banner_without_warnings(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, [
        {"name": "w.pcapng", "role": "wireless", "frame_count": 1, "warnings": []},
    ])
    html = client.get("/analysis/warn1").text
    assert "입력 파일 경고" not in html


def test_old_result_without_sources_renders(tmp_path, monkeypatch):
    """구버전 결과(sources 없음)도 분석 페이지가 그대로 뜬다 (하위 호환)."""
    _store(tmp_path, monkeypatch, None)  # sources 키 자체를 지운다
    p = tmp_path / "warn1.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["structured"].pop("sources")
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert client.get("/analysis/warn1").status_code == 200
