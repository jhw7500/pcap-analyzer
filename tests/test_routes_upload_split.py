"""POST /api/upload의 **분할 캡처 이어붙이기** (스니퍼 파일 로테이션).

기준 캡처(file)와 유선 캡처(wired_file)에 조각을 여러 개 올리면 mergecap으로
시간순 병합해 **하나의 캡처**로 분석한다. 같은 구간을 다른 위치에서 동시에
관측한 wireless_files(다중 스니퍼 — TSF 정렬 + dedup)와는 다른 경로다.
"""
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from analyzer.core.split_merge import merge_split_captures, merged_display_name
from app import app
from routes import upload as upload_module

client = TestClient(app)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20  # little-endian pcap


def _ok_result(pcap_path, **kwargs):
    wireless_paths = kwargs.get("wireless_paths") or []
    sources = [
        {"name": f"tmpW{i}", "role": "wireless", "frame_count": 1, "warnings": []}
        for i in range(1 + len(wireless_paths))
    ]
    if kwargs.get("wired_path"):
        sources.append(
            {"name": "tmpWired", "role": "wired", "frame_count": None, "warnings": []}
        )
    return {
        "id": "t1", "pcap_name": "x", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": {"sources": sources},
        "text_sections": [],
    }


class TestMergedDisplayName:
    def test_single_keeps_original_name(self):
        assert merged_display_name(["a.pcapng"]) == "a.pcapng"

    def test_multiple_shows_part_count(self):
        # 합쳐진 결과임을 숨기지 않는다 — 조각 수를 그대로 노출.
        assert merged_display_name(["a.pcapng", "b.pcapng", "c.pcapng"]) == \
            "a.pcapng 외 2개 (이어붙임)"

    def test_empty(self):
        assert merged_display_name([]) == ""


class TestMergeSplitCaptures:
    def test_rejects_single_path(self, tmp_path):
        ok, reason = merge_split_captures([str(tmp_path / "a.pcap")], str(tmp_path / "o.pcapng"))
        assert ok is False
        assert "2개 미만" in reason

    def test_missing_binary_reported(self, tmp_path):
        ok, reason = merge_split_captures(
            [str(tmp_path / "a"), str(tmp_path / "b")],
            str(tmp_path / "o.pcapng"),
            mergecap_path="/nonexistent/mergecap-xyz",
        )
        assert ok is False
        assert "찾을 수 없다" in reason

    def test_nonzero_exit_surfaces_stderr(self, tmp_path):
        bad_a = tmp_path / "a.pcap"
        bad_b = tmp_path / "b.pcap"
        bad_a.write_bytes(b"not a pcap at all")
        bad_b.write_bytes(b"neither is this")
        out = tmp_path / "o.pcapng"
        ok, reason = merge_split_captures([str(bad_a), str(bad_b)], str(out),
                                          mergecap_path="/bin/false")
        assert ok is False
        assert "exit" in reason

    def test_empty_output_treated_as_failure(self, tmp_path):
        a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
        a.write_bytes(PCAP_MAGIC)
        b.write_bytes(PCAP_MAGIC)
        out = tmp_path / "o.pcapng"
        # exit 0을 내지만 산출물을 만들지 않는 가짜 mergecap
        ok, reason = merge_split_captures([str(a), str(b)], str(out),
                                          mergecap_path="/bin/true")
        assert ok is False
        assert "빈 결과" in reason


def _have_mergecap() -> bool:
    try:
        subprocess.run(["mergecap", "-v"], capture_output=True, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(not _have_mergecap(), reason="mergecap 없음")
class TestRealMerge:
    def test_two_real_captures_concatenate_frame_counts(self, tmp_path):
        """실제 mergecap으로 조각 2개를 합치면 프레임 수가 더해진다."""
        import shutil

        fixture = Path(__file__).parent / "fixtures" / "sample_basic.pcap"
        if not fixture.exists():
            pytest.skip("sample_basic.pcap 픽스처 없음")
        a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
        shutil.copy(fixture, a)
        shutil.copy(fixture, b)
        out = tmp_path / "merged.pcapng"

        ok, reason = merge_split_captures([str(a), str(b)], str(out))
        assert ok, reason
        assert out.stat().st_size > 0

        def _count(p):
            r = subprocess.run(["capinfos", "-c", "-M", str(p)],
                               capture_output=True, text=True, timeout=60)
            for line in r.stdout.splitlines():
                if "Number of packets" in line:
                    return int(line.split(":")[1].strip())
            return None

        n_one, n_merged = _count(a), _count(out)
        if n_one is None or n_merged is None:
            pytest.skip("capinfos 없음")
        assert n_merged == n_one * 2


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
class TestUploadRoute:
    @pytest.fixture(autouse=True)
    def _stub_mergecap(self):
        """mergecap **감지 결과**를 고정한다 — 이 클래스는 병합 오케스트레이션
        (조각을 몇 번 어떤 인자로 합치는지, 실패를 어떻게 표면화하는지)을 보므로
        호스트에 mergecap이 깔려 있는지에 결과가 달라지면 안 된다. 실제 병합은
        각 테스트가 `merge_split_captures`를 patch해 대신한다.

        고정하지 않으면 mergecap 없는 러너(CI)에서 라우트가 병합 호출 **전에**
        MERGECAP_MISSING으로 끊겨, patch한 가짜 병합에 도달하지 못한다.
        감지 부재 자체를 검증하는 테스트는 안쪽에서 다시 patch해 이 stub을 덮는다.
        """
        with patch("routes.upload.config.detect_mergecap",
                   return_value="/usr/bin/mergecap"):
            yield

    def test_single_file_does_not_invoke_mergecap(self, mock_run, _tshark,
                                                  tmp_path, monkeypatch):
        """조각 1개면 기존 경로 그대로 — mergecap을 부르지 않는다."""
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        with patch("routes.upload.merge_split_captures") as mock_merge:
            resp = client.post("/api/upload", files=[
                ("file", ("only.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 200
        mock_merge.assert_not_called()

    def test_split_parts_merged_into_one_capture(self, mock_run, _tshark,
                                                 tmp_path, monkeypatch):
        """조각 3개 → mergecap 1회 → 파이프라인엔 단일 경로만 전달."""
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        merged = tmp_path / "merged-out.pcapng"

        def fake_merge(paths, out_path, mergecap_path=None):
            assert len(paths) == 3          # 조각 전부 넘어와야 한다
            Path(out_path).write_bytes(PCAP_MAGIC)
            merged.write_bytes(b"x")
            return True, ""

        with patch("routes.upload.merge_split_captures", side_effect=fake_merge) as mm:
            resp = client.post("/api/upload", files=[
                ("file", ("cap_1.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("cap_2.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("cap_3.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 200, resp.text
        assert mm.call_count == 1
        # 다중 스니퍼 경로가 아니라 단일 캡처로 들어가야 한다.
        assert not mock_run.call_args.kwargs.get("wireless_paths")

        saved = json.loads((tmp_path / "t1.json").read_text(encoding="utf-8"))
        assert saved["pcap_name"] == "cap_1.pcapng 외 2개 (이어붙임)"

    def test_wired_split_parts_merged(self, mock_run, _tshark, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result

        def fake_merge(paths, out_path, mergecap_path=None):
            Path(out_path).write_bytes(PCAP_MAGIC)
            return True, ""

        with patch("routes.upload.merge_split_captures", side_effect=fake_merge) as mm:
            resp = client.post("/api/upload", files=[
                ("file", ("w.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("wired_file", ("wired_1.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("wired_file", ("wired_2.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 200, resp.text
        # 무선은 조각 1개라 병합 없음, 유선만 병합 → 1회
        assert mm.call_count == 1
        assert mock_run.call_args.kwargs.get("wired_path")

    def test_merge_failure_surfaces_reason(self, mock_run, _tshark, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        with patch("routes.upload.merge_split_captures",
                   return_value=(False, "encapsulation 불일치")):
            resp = client.post("/api/upload", files=[
                ("file", ("a.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("b.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 400
        body = resp.json()
        assert body["code"] == "MERGE_FAILED"
        assert "encapsulation 불일치" in body["error"]   # 실패 사유가 그대로 표면화

    def test_mergecap_missing_reported(self, mock_run, _tshark, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        with patch("routes.upload.config.detect_mergecap", return_value=None):
            resp = client.post("/api/upload", files=[
                ("file", ("a.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("b.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        # 503 — 서버 버그(500)가 아니라 환경 의존성 부재다.
        assert resp.status_code == 503
        assert resp.json()["code"] == "MERGECAP_MISSING"

    def test_too_many_split_parts_rejected(self, mock_run, _tshark, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        # 상한값은 상수에서 읽는다 — 상한을 조정해도 "1개 초과 시 거부" 의미가 유지된다.
        from routes.upload import _MAX_SPLIT_PARTS
        files = [("file", (f"p{i}.pcapng", PCAP_MAGIC, "application/octet-stream"))
                 for i in range(_MAX_SPLIT_PARTS + 1)]
        resp = client.post("/api/upload", files=files)
        assert resp.status_code == 400
        assert resp.json()["code"] == "TOO_MANY_FILES"

    def test_bad_part_cleans_up_earlier_parts(self, mock_run, _tshark,
                                              tmp_path, monkeypatch):
        """조각 하나가 잘못되면 앞서 저장한 조각 임시파일도 남기지 않는다."""
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        saved_paths = []
        real_save = __import__("routes.upload", fromlist=["_save_pcap_upload"])._save_pcap_upload

        async def tracking_save(f, budget=None):
            path, err = await real_save(f, budget)
            if path:
                saved_paths.append(path)
            return path, err

        with patch("routes.upload._save_pcap_upload", side_effect=tracking_save):
            resp = client.post("/api/upload", files=[
                ("file", ("good.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("bad.txt", PCAP_MAGIC, "application/octet-stream")),  # 확장자 불가
            ])
        assert resp.status_code == 400
        assert resp.json()["code"] == "INVALID_EXT"
        assert saved_paths, "첫 조각은 저장됐어야 한다"
        for p in saved_paths:
            assert not Path(p).exists(), f"임시 파일 누수: {p}"



@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
class TestMergeOffEventLoop:
    """mergecap은 블로킹 subprocess다 — async 핸들러에서 직접 부르면 병합이 끝날
    때까지 이벤트 루프 전체가 멈춰 진행률 폴링·취소·다른 요청이 모두 막힌다.
    분석 본체가 executor로 나가 있는 것과 같은 규약을 병합에도 적용한다.
    """

    @pytest.fixture(autouse=True)
    def _stub_mergecap(self):
        with patch("routes.upload.config.detect_mergecap",
                   return_value="/usr/bin/mergecap"):
            yield

    def test_merge_runs_in_executor_not_on_the_loop(self, mock_run, _tshark,
                                                    tmp_path, monkeypatch):
        import asyncio

        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        on_loop = []

        def fake_merge(paths, out_path, mergecap_path=None):
            # 이벤트 루프 스레드에서 돌면 get_running_loop()가 성공한다.
            try:
                asyncio.get_running_loop()
                on_loop.append(True)
            except RuntimeError:
                on_loop.append(False)
            Path(out_path).write_bytes(PCAP_MAGIC)
            return True, ""

        with patch("routes.upload.merge_split_captures", side_effect=fake_merge):
            resp = client.post("/api/upload", files=[
                ("file", ("a.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("b.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 200, resp.text
        assert on_loop == [False], "mergecap이 이벤트 루프를 점유했다"


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
class TestRequestTotalBudget:
    """파일별 상한만으로는 한 요청의 디스크 사용량을 못 막는다.

    관측점 5개(주 캡처·유선·추가 무선 3) × 분할 조각 32개 × 파일 상한 1GB =
    이론상 160GB가 한 요청에 들어온다. 조각마다 따로 검사하면 전부 통과한다.
    """

    @pytest.fixture(autouse=True)
    def _stub_mergecap(self):
        with patch("routes.upload.config.detect_mergecap",
                   return_value="/usr/bin/mergecap"):
            yield

    def test_sum_across_parts_is_capped(self, mock_run, _tshark, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        # 조각 하나하나는 파일 상한을 한참 밑돌지만 합계는 넘는다.
        monkeypatch.setattr(upload_module, "_MAX_REQUEST_TOTAL_BYTES", 3 * 1024)
        blob = PCAP_MAGIC + b"\x00" * 2048

        resp = client.post("/api/upload", files=[
            ("file", ("a.pcapng", blob, "application/octet-stream")),
            ("file", ("b.pcapng", blob, "application/octet-stream")),
        ])
        assert resp.status_code == 413, resp.text
        assert "요청 합계 상한" in resp.json()["error"]

    def test_within_budget_still_passes(self, mock_run, _tshark, tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        monkeypatch.setattr(upload_module, "_MAX_REQUEST_TOTAL_BYTES", 1024 * 1024)

        def fake_merge(paths, out_path, mergecap_path=None):
            Path(out_path).write_bytes(PCAP_MAGIC)
            return True, ""

        with patch("routes.upload.merge_split_captures", side_effect=fake_merge):
            resp = client.post("/api/upload", files=[
                ("file", ("a.pcapng", PCAP_MAGIC, "application/octet-stream")),
                ("file", ("b.pcapng", PCAP_MAGIC, "application/octet-stream")),
            ])
        assert resp.status_code == 200, resp.text

    def test_rejected_request_leaves_no_temp_files(self, mock_run, _tshark,
                                                   tmp_path, monkeypatch):
        import config
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        mock_run.side_effect = _ok_result
        monkeypatch.setattr(upload_module, "_MAX_REQUEST_TOTAL_BYTES", 3 * 1024)
        blob = PCAP_MAGIC + b"\x00" * 2048

        saved = []
        real_save = upload_module._save_pcap_upload

        async def tracking(f, budget=None):
            path, err = await real_save(f, budget)
            if path:
                saved.append(path)
            return path, err

        with patch("routes.upload._save_pcap_upload", side_effect=tracking):
            resp = client.post("/api/upload", files=[
                ("file", ("a.pcapng", blob, "application/octet-stream")),
                ("file", ("b.pcapng", blob, "application/octet-stream")),
            ])
        assert resp.status_code == 413
        assert saved, "첫 조각은 저장됐어야 이 테스트가 의미를 갖는다"
        assert not [p for p in saved if Path(p).exists()], "거부 후 임시파일이 남았다"


class TestUploadBudgetAccounting:
    def test_rejected_chunk_is_not_charged(self):
        """거부된 청크는 잔액에서 빠지면 안 된다 — 재시도가 생기면 정상 청크가
        애먼 이유로 거부된다."""
        b = upload_module._UploadBudget(limit=100)
        assert b.add(60) and b.used == 60
        assert not b.add(50)            # 110 > 100 → 거부
        assert b.used == 60, "거부된 청크가 계상됐다"
        assert b.add(40) and b.used == 100   # 남은 잔액은 그대로 쓸 수 있어야 한다
