"""FastAPI 라우트 테스트."""

import json
from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


class TestIndexPage:
    def test_get_index(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "WLAN Pcap Analyzer" in resp.text

    def test_settings_link(self):
        resp = client.get("/")
        assert "/settings" in resp.text


class TestSettingsPage:
    def test_get_settings(self):
        resp = client.get("/settings")
        assert resp.status_code == 200
        assert "tshark" in resp.text.lower()


class TestProgressAPI:
    def test_get_progress(self):
        resp = client.get("/api/progress")
        assert resp.status_code == 200
        data = resp.json()
        assert "pct" in data
        assert "msg" in data


class TestAnalysisAPI:
    def test_not_found(self):
        resp = client.get("/analysis/nonexistent_id_12345")
        assert resp.status_code == 404

    def test_api_not_found(self):
        resp = client.get("/api/analysis/nonexistent_id_12345")
        assert resp.status_code == 404

    def test_delete_not_found(self):
        resp = client.delete("/api/analysis/nonexistent_id_12345")
        assert resp.status_code == 404

    def test_text_not_found(self):
        resp = client.get("/api/analysis/nonexistent_id_12345/text")
        assert resp.status_code == 404

    def test_invalid_analysis_id_returns_400(self):
        resp = client.get("/api/analysis/bad..id")
        assert resp.status_code == 400
        assert resp.json()["code"] == "INVALID_ANALYSIS_ID"


class TestUploadValidation:
    def test_no_tshark_error(self):
        # 실제 tshark가 없는 환경에서도 에러 메시지 확인 가능
        # tshark가 있으면 다른 에러 (파일 형식 등)
        resp = client.post(
            "/api/upload",
            files={"file": ("test.txt", b"not a pcap", "application/octet-stream")},
        )
        assert resp.status_code in (400, 500)

    def test_invalid_extension(self):
        resp = client.post(
            "/api/upload",
            files={"file": ("test.pdf", b"data", "application/pdf")},
        )
        # tshark 없으면 500, 있으면 400 (확장자 체크)
        assert resp.status_code in (400, 500)


class TestCancelAPI:
    def test_cancel_no_running(self):
        resp = client.post("/api/cancel")
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_running_analysis"


class TestPerJobAPI:
    def test_get_progress_unknown_job_returns_404(self):
        resp = client.get("/api/progress/unknown-job-id-xxx")
        assert resp.status_code == 404
        assert "error" in resp.json()

    def test_cancel_unknown_job_returns_404(self):
        resp = client.post("/api/cancel/unknown-job-id-xxx")
        assert resp.status_code == 404
        assert "error" in resp.json()


class TestAIReviewAPI:
    def test_review_not_found(self):
        resp = client.post("/api/ai/review/nonexistent_id_12345")
        assert resp.status_code == 404
