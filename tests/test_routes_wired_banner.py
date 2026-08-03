"""분석 페이지 상단 입력 파일 경고 배너 (Jinja 서버 렌더)."""
import json
import re

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


def test_result_without_structured_key_renders(tmp_path, monkeypatch):
    """structured 키 자체가 없는 (더 오래된) 결과도 배너 렌더링에서 500을 내지 않는다."""
    _store(tmp_path, monkeypatch, [])
    p = tmp_path / "warn1.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data.pop("structured")
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert client.get("/analysis/warn1").status_code == 200


# --------------------------------------------------------------------------
# 업로드 파일명 → result_json 스크립트 삽입 (PR #22 8라운드 — 저장형 XSS)
# --------------------------------------------------------------------------


def _data_script(html: str) -> str:
    """analysis.html의 `const DATA = {...};`에 실제로 심긴 JSON 텍스트."""
    m = re.search(r"const DATA = (.*?);\n", html, re.S)
    assert m is not None, "result_json 스크립트 블록을 찾지 못했다"
    return m.group(1)


def test_filename_cannot_break_out_of_result_json_script(tmp_path, monkeypatch):
    """업로드 파일명은 structured.sources에 실려 <script> 안 JSON으로 삽입된다 —
    json.dumps가 <,>를 이스케이프하지 않으므로 "</script>"가 든 파일명 하나로
    스크립트 블록이 닫히고 그 뒤가 마크업으로 해석된다(저장형 XSS)."""
    evil = "</script><script>alert(1)</script>.pcapng"
    _store(tmp_path, monkeypatch, [
        {"name": evil, "role": "wired", "frame_count": None,
         "warnings": ["무선(802.11) 캡처다"]},  # 배너(Jinja 자동escape) 경로도 함께 탄다
    ])
    resp = client.get("/analysis/warn1")
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text  # 어느 싱크로도 원문이 안 나온다
    data_js = _data_script(resp.text)
    assert "</script>" not in data_js
    assert "\\u003c/script\\u003e" in data_js
    # 이스케이프해도 브라우저가 파싱해 얻는 값은 원본 그대로여야 한다.
    assert json.loads(data_js)["sources"][0]["name"] == evil


def test_line_separator_in_filename_is_escaped(tmp_path, monkeypatch):
    """U+2028/U+2029는 JSON에선 합법이지만 (ES2019 이전) JS 소스에선 줄바꿈으로
    취급돼 스크립트를 깨뜨린다 — 스크립트에 심을 때는 함께 이스케이프한다."""
    evil = "a\u2028b\u2029c.pcapng"
    _store(tmp_path, monkeypatch, [
        {"name": evil, "role": "wired", "frame_count": None, "warnings": []},
    ])
    resp = client.get("/analysis/warn1")
    assert resp.status_code == 200
    data_js = _data_script(resp.text)
    assert "\u2028" not in data_js and "\u2029" not in data_js
    assert json.loads(data_js)["sources"][0]["name"] == evil


def test_normal_result_json_stays_readable(tmp_path, monkeypatch):
    """정상 결과는 그대로 — 한글이 \\uXXXX로 부풀지 않고(ensure_ascii=False 유지)
    JSON도 유효하다."""
    _store(tmp_path, monkeypatch, [
        {"name": "유선캡처.pcapng", "role": "wired", "frame_count": None, "warnings": []},
    ])
    data_js = _data_script(client.get("/analysis/warn1").text)
    assert "유선캡처.pcapng" in data_js
    assert json.loads(data_js)["sources"][0]["role"] == "wired"
