"""routes/upload.py 보강 커버리지 — 진행률, 취소, 업로드 분기, prune 동작."""
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import config
from app import app
from routes import upload as upload_module

client = TestClient(app)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
VALID_PCAP_HEAD = PCAP_MAGIC + b"\x00" * 1024


@pytest.fixture(autouse=True)
def _reset_jobs():
    upload_module._jobs.clear()
    yield
    upload_module._jobs.clear()


def _make_job(active: bool = True, msg: str = "분석 중", pct: int = 10, created: float | None = None):
    return {
        "msg": msg,
        "pct": pct,
        "active": active,
        "created": created if created is not None else time.time(),
        "cancel": threading.Event(),
        "tmp": "",
    }


class TestCleanupTmps:
    def test_continues_after_individual_unlink_failure(self, tmp_path, monkeypatch):
        """한 경로의 unlink가 raise(예: Windows 파일 잠금)해도 나머지 경로는
        계속 정리돼야 한다 — 감싸지 않으면 첫 실패에서 예외가 전파돼 그 뒤
        경로 전부가 누수된다(PR #23 리뷰 2라운드 Finding C)."""
        p1 = tmp_path / "a.pcap"
        p2 = tmp_path / "b.pcap"
        p3 = tmp_path / "c.pcap"
        for p in (p1, p2, p3):
            p.write_bytes(b"x")

        original_unlink = Path.unlink

        def _flaky_unlink(self, missing_ok=False):
            if self == p1:
                raise OSError("simulated lock")
            return original_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)

        upload_module._cleanup_tmps(str(p1), str(p2), str(p3))

        assert p1.exists()      # 잠금 실패 — 그대로 남음(예외는 흡수)
        assert not p2.exists()  # 첫 실패 이후에도 계속 정리됨
        assert not p3.exists()


class TestIndexCorruptJson:
    def test_corrupt_analysis_json_skipped(self):
        data_dir = config.ensure_data_dir()
        bad = data_dir / "_corrupt_test_xx.json"
        bad.write_text("{not valid json")
        try:
            resp = client.get("/")
            assert resp.status_code == 200
        finally:
            bad.unlink(missing_ok=True)


class TestProgressLatestWithJobs:
    def test_returns_active_job_progress(self):
        upload_module._jobs["job-active"] = _make_job(active=True, pct=42)
        resp = client.get("/api/progress")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pct"] == 42
        assert data["active"] is True

    def test_returns_idle_when_no_active(self):
        # active 없으면 finished가 있어도 idle 0% (이전 분석 잔존 표시 회피)
        upload_module._jobs["job-done"] = _make_job(active=False, msg="완료", pct=100)
        resp = client.get("/api/progress")
        assert resp.status_code == 200
        body = resp.json()
        assert body["active"] is False
        assert body["pct"] == 0
        assert body["msg"] == ""


class TestProgressById:
    def test_returns_specific_job(self):
        upload_module._jobs["job-id-1"] = _make_job(pct=30, msg="추출 중")
        resp = client.get("/api/progress/job-id-1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["pct"] == 30
        assert body["msg"] == "추출 중"


class TestCancelJob:
    def test_cancel_running_sets_event(self):
        ev = threading.Event()
        upload_module._jobs["job-r"] = {
            **_make_job(active=True),
            "cancel": ev,
        }
        resp = client.post("/api/cancel/job-r")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"
        assert ev.is_set()

    def test_cancel_already_finished(self):
        upload_module._jobs["job-f"] = _make_job(active=False)
        resp = client.post("/api/cancel/job-f")
        assert resp.status_code == 200
        assert resp.json()["status"] == "already_finished"

    def test_cancel_all_only_active(self):
        ev1 = threading.Event()
        upload_module._jobs["j1"] = {**_make_job(active=True), "cancel": ev1}
        upload_module._jobs["j2"] = _make_job(active=False)
        resp = client.post("/api/cancel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "cancelled"
        assert "j1" in body["job_ids"]
        assert "j2" not in body["job_ids"]
        assert ev1.is_set()


class TestUploadValidation:
    def test_no_tshark_returns_500(self):
        with patch("routes.upload.config.detect_tshark", return_value=None):
            resp = client.post(
                "/api/upload",
                files={"file": ("x.pcap", b"data", "application/octet-stream")},
            )
        assert resp.status_code == 500
        assert resp.json()["code"] == "TSHARK_MISSING"

    def test_invalid_extension_returns_400(self):
        with patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("x.txt", b"data", "application/octet-stream")},
            )
        assert resp.status_code == 400
        assert resp.json()["code"] == "INVALID_EXT"

    def test_invalid_magic_returns_400(self):
        with patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("x.pcap", b"NOT_PCAP_DATA_HERE", "application/octet-stream")},
            )
        assert resp.status_code == 400
        assert resp.json()["code"] == "INVALID_MAGIC"

    def test_empty_file_returns_400(self):
        with patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("empty.pcap", b"", "application/octet-stream")},
            )
        assert resp.status_code == 400
        assert resp.json()["code"] == "EMPTY_FILE"

    def test_file_too_large_returns_413(self):
        with patch("routes.upload.config.max_upload_size", return_value=64), \
             patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            payload = PCAP_MAGIC + b"\x00" * 200
            resp = client.post(
                "/api/upload",
                files={"file": ("big.pcap", payload, "application/octet-stream")},
            )
        assert resp.status_code == 413
        assert resp.json()["code"] == "FILE_TOO_LARGE"


class TestUploadAnalysisOutcomes:
    def test_run_analysis_error_returns_500(self):
        with patch("routes.upload.run_analysis", return_value={"error": "boom"}), \
             patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("ok.pcap", VALID_PCAP_HEAD, "application/octet-stream")},
            )
        assert resp.status_code == 500
        body = resp.json()
        assert body["code"] == "NO_FRAMES"
        assert "job_id" in body

    def test_run_analysis_error_with_code_returns_400(self):
        """pipeline이 error_code를 명시하면(예: 잘못된 시간 필터) NO_FRAMES(500)
        로 뭉개지 않고 그 코드로 400을 반환한다(PR #23 리뷰 6라운드 Finding A)."""
        with patch("routes.upload.run_analysis", return_value={
            "error": "시간 필터를 해석할 수 없다: not-a-date",
            "error_code": "INVALID_TIME_FILTER",
        }), patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("ok.pcap", VALID_PCAP_HEAD, "application/octet-stream")},
            )
        assert resp.status_code == 400
        body = resp.json()
        assert body["code"] == "INVALID_TIME_FILTER"
        assert "job_id" in body

    def test_run_analysis_error_with_unknown_code_falls_back_to_500(self):
        """error_code가 ErrorCode 카탈로그에 없는 값이면(방어적 가드) 기존
        NO_FRAMES(500)로 폴백한다 — 예상 밖 값으로 크래시하지 않는다."""
        with patch("routes.upload.run_analysis", return_value={
            "error": "boom", "error_code": "NOT_A_REAL_CODE",
        }), patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("ok.pcap", VALID_PCAP_HEAD, "application/octet-stream")},
            )
        assert resp.status_code == 500
        assert resp.json()["code"] == "NO_FRAMES"

    def test_run_analysis_cancelled_returns_499(self):
        with patch("routes.upload.run_analysis", return_value={"cancelled": True}), \
             patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            resp = client.post(
                "/api/upload",
                files={"file": ("ok.pcap", VALID_PCAP_HEAD, "application/octet-stream")},
            )
        assert resp.status_code == 499
        body = resp.json()
        assert body["code"] == "CANCELLED"
        assert "job_id" in body

    def test_run_analysis_success_writes_result(self):
        fake_id = "test_upload_success_zzz"
        result_path = config.ensure_data_dir() / f"{fake_id}.json"
        result_path.unlink(missing_ok=True)
        fake_result = {
            "id": fake_id,
            "frame_count": 10,
            "structured": {},
            "text_sections": [],
        }
        try:
            with patch("routes.upload.run_analysis", return_value=fake_result), \
                 patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
                resp = client.post(
                    "/api/upload",
                    files={"file": ("ok.pcap", VALID_PCAP_HEAD, "application/octet-stream")},
                )
            assert resp.status_code == 200
            body = resp.json()
            assert body["id"] == fake_id
            assert body["redirect"] == f"/analysis/{fake_id}"
            assert "job_id" in body
            assert result_path.exists()
        finally:
            result_path.unlink(missing_ok=True)


class TestPruneJobs:
    def test_prune_keeps_recent_n(self):
        from routes.upload import _JOBS_MAX
        for i in range(_JOBS_MAX + 5):
            upload_module._jobs[f"old-{i}"] = _make_job(active=False, created=float(i))
        with patch("routes.upload.run_analysis", return_value={"cancelled": True}), \
             patch("routes.upload.config.detect_tshark", return_value="/usr/bin/tshark"):
            client.post(
                "/api/upload",
                files={"file": ("ok.pcap", VALID_PCAP_HEAD, "application/octet-stream")},
            )
        assert len(upload_module._jobs) <= _JOBS_MAX
