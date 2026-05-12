"""app.py __main__ 블록 env override 동작 검증."""
from unittest import mock


def test_run_dev_server_defaults(monkeypatch):
    """env 미설정 시 host=0.0.0.0, port=8000, reload=True."""
    monkeypatch.delenv("PCAP_HOST", raising=False)
    monkeypatch.delenv("PCAP_PORT", raising=False)
    monkeypatch.delenv("PCAP_DEV_RELOAD", raising=False)

    import app
    with mock.patch.object(app.uvicorn, "run") as mock_run:
        app._run_dev_server()
        kwargs = mock_run.call_args.kwargs
        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["port"] == 8000
        assert kwargs["reload"] is True


def test_run_dev_server_env_override(monkeypatch):
    """PCAP_HOST/PORT/DEV_RELOAD가 우선."""
    monkeypatch.setenv("PCAP_HOST", "127.0.0.1")
    monkeypatch.setenv("PCAP_PORT", "9000")
    monkeypatch.setenv("PCAP_DEV_RELOAD", "false")

    import app
    with mock.patch.object(app.uvicorn, "run") as mock_run:
        app._run_dev_server()
        kwargs = mock_run.call_args.kwargs
        assert kwargs["host"] == "127.0.0.1"
        assert kwargs["port"] == 9000
        assert kwargs["reload"] is False


def test_run_dev_server_reload_case_insensitive(monkeypatch):
    """PCAP_DEV_RELOAD는 대소문자 무관."""
    monkeypatch.setenv("PCAP_DEV_RELOAD", "FALSE")
    import app
    with mock.patch.object(app.uvicorn, "run") as mock_run:
        app._run_dev_server()
        assert mock_run.call_args.kwargs["reload"] is False
