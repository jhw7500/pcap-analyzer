"""대용량 결과에서의 서버 경로 최적화 — 메타 사이드카 / 결과 파싱 캐시 / gzip.

2시간 캡처 결과는 33MB라 다음 세 경로가 저장 건수·요청 수에 비례해 비싸졌다:
- 홈 화면이 결과 JSON을 **전량** 파싱 (실측 45건 847MB에서 8.6초)
- 같은 결과를 요청마다 다시 파싱 (요청당 0.3~0.8초)
- 34MB 응답을 무압축 전송
"""
import gzip
import time
import json
from unittest.mock import patch

from fastapi.testclient import TestClient

import config
from app import app
from routes import analysis as analysis_module
from routes import upload as upload_module

client = TestClient(app)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20


def _result(analysis_id="a1", frames=123):
    return {
        "id": analysis_id, "pcap_name": "cap.pcapng", "pcap_size": 1,
        "frame_count": frames, "analyzed_at": "2026-08-10 11:00:00 KST",
        "tshark_version": "4.4.9", "tshark_path": "tshark",
        "structured": {"sources": [], "overview": {"total_frames": frames}},
        "text_sections": [],
    }


def _write_result(tmp_path, analysis_id="a1", frames=123):
    path = tmp_path / f"{analysis_id}.json"
    path.write_text(json.dumps(_result(analysis_id, frames), ensure_ascii=False),
                    encoding="utf-8")
    return path


class TestMetaSidecar:
    def test_saved_upload_writes_sidecar(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        with patch("routes.upload.config.detect_tshark", return_value="tshark"), \
             patch("routes.upload.run_analysis", side_effect=lambda p, **k: _result("t1", 999)):
            resp = client.post("/api/upload", files=[
                ("file", ("c.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 200
        meta = tmp_path / "t1.meta.json"
        assert meta.exists(), "저장 직후 사이드카가 있어야 한다"
        loaded = json.loads(meta.read_text(encoding="utf-8"))
        assert loaded == {
            "id": "t1", "pcap_name": "c.pcapng",
            "frame_count": 999, "analyzed_at": "2026-08-10 11:00:00 KST",
        }
        # 사이드카는 본 결과의 극히 일부여야 의미가 있다.
        assert meta.stat().st_size < (tmp_path / "t1.json").stat().st_size

    def test_home_reads_sidecar_without_parsing_result(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 4242)
        upload_module.write_analysis_meta("a1", _result("a1", 4242))
        # 본 결과를 읽으면 실패하도록 망가뜨려도 홈은 사이드카만 보고 성공해야 한다.
        (tmp_path / "a1.json").write_text("{ 깨진 JSON", encoding="utf-8")

        with patch("routes.upload.config.detect_tshark", return_value="tshark"):
            resp = client.get("/")
        assert resp.status_code == 200
        assert "4,242" in resp.text or "4242" in resp.text

    def test_missing_sidecar_falls_back_and_backfills(self, tmp_path, monkeypatch):
        """구버전 결과(사이드카 없음)는 1회 파싱 후 사이드카를 만들어 둔다."""
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "old1", 777)
        assert not (tmp_path / "old1.meta.json").exists()

        with patch("routes.upload.config.detect_tshark", return_value="tshark"):
            resp = client.get("/")
        assert resp.status_code == 200
        assert (tmp_path / "old1.meta.json").exists(), "폴백 후 사이드카가 생겨야 한다"
        assert json.loads((tmp_path / "old1.meta.json").read_text(encoding="utf-8"))["frame_count"] == 777

    def test_corrupt_sidecar_recovers_from_result(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 555)
        (tmp_path / "a1.meta.json").write_text("깨진", encoding="utf-8")

        with patch("routes.upload.config.detect_tshark", return_value="tshark"):
            resp = client.get("/")
        assert resp.status_code == 200
        assert json.loads((tmp_path / "a1.meta.json").read_text(encoding="utf-8"))["frame_count"] == 555

    def test_sidecar_not_listed_as_analysis(self, tmp_path, monkeypatch):
        """사이드카가 결과 목록에 분석 항목으로 잡히면 안 된다."""
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 100)
        upload_module.write_analysis_meta("a1", _result("a1", 100))

        with patch("routes.upload.config.detect_tshark", return_value="tshark"):
            resp = client.get("/")
        assert resp.status_code == 200
        # 목록 링크는 /analysis/a1 하나뿐 — a1.meta 항목이 생기면 안 된다.
        assert "/analysis/a1.meta" not in resp.text
        assert resp.text.count('href="/analysis/a1"') == 1

    def test_delete_removes_sidecar(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 100)
        upload_module.write_analysis_meta("a1", _result("a1", 100))
        assert (tmp_path / "a1.meta.json").exists()

        resp = client.delete("/api/analysis/a1")
        assert resp.status_code == 200
        assert not (tmp_path / "a1.json").exists()
        assert not (tmp_path / "a1.meta.json").exists(), "사이드카도 함께 지워야 한다"


class TestResultCache:
    def setup_method(self):
        analysis_module._invalidate_result_cache()

    def test_second_request_does_not_reparse(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 321)

        real_loads = json.loads
        calls = []

        def counting_loads(*a, **k):
            calls.append(1)
            return real_loads(*a, **k)

        with patch("routes.analysis.json.loads", side_effect=counting_loads):
            r1 = client.get("/api/analysis/a1")
            n_after_first = len(calls)
            r2 = client.get("/api/analysis/a1")
            n_after_second = len(calls)

        assert r1.status_code == r2.status_code == 200
        assert n_after_first >= 1
        assert n_after_second == n_after_first, "두 번째 요청은 재파싱하면 안 된다"
        assert r1.json()["frame_count"] == r2.json()["frame_count"] == 321

    def test_file_change_invalidates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        path = _write_result(tmp_path, "a1", 100)
        assert client.get("/api/analysis/a1").json()["frame_count"] == 100

        # 내용·크기가 달라지면 캐시 키(mtime+size)가 달라져 새로 읽어야 한다.
        path.write_text(json.dumps(_result("a1", 20000), ensure_ascii=False), encoding="utf-8")
        assert client.get("/api/analysis/a1").json()["frame_count"] == 20000

    def test_delete_invalidates_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 100)
        assert client.get("/api/analysis/a1").status_code == 200
        assert client.delete("/api/analysis/a1").status_code == 200
        assert client.get("/api/analysis/a1").status_code == 404

    def test_cache_is_bounded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        for i in range(5):
            _write_result(tmp_path, f"a{i}", i)
            assert client.get(f"/api/analysis/a{i}").status_code == 200
        assert len(analysis_module._result_cache) <= analysis_module._RESULT_CACHE_MAX


class TestGzip:
    def test_large_response_is_compressed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        # 압축 효과가 드러나도록 반복성 높은 큰 결과를 만든다.
        big = _result("big", 1)
        big["structured"]["per_second"] = {
            "timeline": [{"epoch": 1000 + i, "total": 10, "retry": 1,
                          "bytes": 1234, "data_bytes": 1000} for i in range(5000)]
        }
        (tmp_path / "big.json").write_text(json.dumps(big, ensure_ascii=False), encoding="utf-8")

        resp = client.get("/api/analysis/big", headers={"Accept-Encoding": "gzip"})
        assert resp.status_code == 200
        assert resp.headers.get("content-encoding") == "gzip"
        # httpx가 이미 풀어 준 본문과, 압축 전송량을 비교
        raw_len = len(resp.content)
        recompressed = len(gzip.compress(resp.content, 6))
        assert recompressed < raw_len / 3, "이 데이터는 압축률이 높아야 한다"

    def test_small_response_not_compressed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        resp = client.get("/api/analysis/nope", headers={"Accept-Encoding": "gzip"})
        # 404 payload는 minimum_size(1024) 미만이라 압축 대상이 아니다.
        assert resp.status_code == 404
        assert resp.headers.get("content-encoding") != "gzip"

    def test_no_accept_encoding_returns_plain(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        _write_result(tmp_path, "a1", 100)
        resp = client.get("/api/analysis/a1", headers={"Accept-Encoding": "identity"})
        assert resp.status_code == 200
        assert resp.headers.get("content-encoding") != "gzip"


class TestResultCacheThreadSafety:
    """결과 캐시는 스레드풀에서 동시에 접근된다.

    `def` 엔드포인트는 FastAPI가 스레드풀로 내보내므로(홈 `index()`와 같은 이유)
    여러 요청이 동시에 이 OrderedDict를 만진다. 개별 dict 연산은 GIL 아래
    원자적이지만 "조회 → 삽입 → LRU 축출"은 아니라, 잠금이 없으면 두 스레드가
    같은 미스를 처리할 때 `popitem`이 이미 빠진 키를 건드려 KeyError가 날 수 있다.

    **이 테스트들의 한계**: 아래 스트레스 테스트는 잠금을 제거해도 통과한다(3회
    확인). GIL 때문에 check-then-act의 경합 창이 수 바이트코드로 좁아 스레드로는
    재현되지 않는다 — 회귀 방지용 smoke이지 잠금의 필요성을 증명하지는 못한다.
    잠금이 실제로 걸려 있는지는 아래 구조 테스트로 고정한다.
    """

    def test_cache_mutations_are_guarded(self):
        """조회·삽입·무효화가 모두 잠금 안에서 일어나는지 구조로 고정한다."""
        import inspect

        for fn in (analysis_module._read_result_cached,
                   analysis_module._invalidate_result_cache):
            src = inspect.getsource(fn)
            assert "with _result_cache_lock" in src, fn.__name__
        # 파싱은 잠금 밖이어야 한다 — 안이면 동시 요청이 직렬화돼 캐시가 병목이 된다.
        read_src = inspect.getsource(analysis_module._read_result_cached)
        parse_line = next(i for i, ln in enumerate(read_src.splitlines())
                          if "json.loads" in ln)
        indent = len(read_src.splitlines()[parse_line]) - len(
            read_src.splitlines()[parse_line].lstrip())
        assert indent <= 8, "json.loads가 잠금 블록 안으로 들어갔다"

    def _write(self, tmp_path, name, frames):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(_result(name, frames)), encoding="utf-8")
        return p

    def test_concurrent_read_and_invalidate_does_not_raise(self, tmp_path):
        import threading

        analysis_module._invalidate_result_cache()
        # 캐시 상한(2)보다 많은 파일을 돌려 축출 경로를 반드시 타게 한다.
        paths = [self._write(tmp_path, f"c{i}", 100 + i) for i in range(6)]
        errors, reads = [], []
        stop = threading.Event()

        def reader(path):
            try:
                while not stop.is_set():
                    got = analysis_module._read_result_cached(path)
                    if got is None:
                        errors.append(f"{path} 파싱 실패")
                        return
                    # 캐시가 뒤섞이면 다른 결과가 돌아온다.
                    if got["id"] != path.stem:
                        errors.append(f"{path.stem} 자리에 {got['id']}")
                        return
                    reads.append(1)
            except Exception as exc:            # 잠금 없으면 여기서 KeyError
                errors.append(repr(exc))

        def invalidator():
            try:
                while not stop.is_set():
                    analysis_module._invalidate_result_cache(paths[0])
                    analysis_module._invalidate_result_cache()
            except Exception as exc:
                errors.append(repr(exc))

        threads = [threading.Thread(target=reader, args=(p,)) for p in paths]
        threads += [threading.Thread(target=invalidator) for _ in range(2)]
        for t in threads:
            t.start()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not errors:
            time.sleep(0.01)        # 바쁜 대기는 워커를 굶겨 경합을 오히려 줄인다
        stop.set()
        for t in threads:
            t.join(timeout=5)
        assert not errors, errors[:3]
        assert reads, "읽기가 한 번도 성공하지 않았다 — 테스트가 무력"

    def test_lru_keeps_at_most_max_entries(self, tmp_path):
        analysis_module._invalidate_result_cache()
        for i in range(5):
            analysis_module._read_result_cached(self._write(tmp_path, f"l{i}", i))
        assert len(analysis_module._result_cache) <= analysis_module._RESULT_CACHE_MAX
        analysis_module._invalidate_result_cache()
