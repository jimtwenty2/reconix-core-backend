import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

RCX_PATH = Path(".agents/skills/reconix-operator/scripts/rcx.py").resolve()


@pytest.fixture(scope="module")
def rcx():
    if not RCX_PATH.exists():
        pytest.fail(f"rcx.py not found at {RCX_PATH}")
    spec = importlib.util.spec_from_file_location("rcx", RCX_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_get_base_url_defaults(rcx, monkeypatch):
    monkeypatch.delenv("RECONIX_CORE_API_URL", raising=False)
    assert rcx.get_base_url() == "http://127.0.0.1:8000"


def test_get_base_url_env_override(rcx, monkeypatch):
    monkeypatch.setenv("RECONIX_CORE_API_URL", "http://localhost:9000/")
    assert rcx.get_base_url() == "http://localhost:9000"


def test_check_status_returns_health_dict(rcx):
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "ok", "version": "0.1.0"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        res = rcx.check_status()
        assert res["status"] == "ok"


def test_get_session_token_requests_and_caches(rcx, tmp_path, monkeypatch):
    cache_file = tmp_path / "session.json"
    monkeypatch.setattr(rcx, "SESSION_CACHE_FILE", cache_file)

    with patch.object(rcx, "request") as mock_req:
        mock_req.return_value = {"token": "fake-session-token-123"}
        token = rcx.get_session_token(force_refresh=True)
        assert token == "fake-session-token-123"
        assert cache_file.exists()
        cached = json.loads(cache_file.read_text())
        assert cached["token"] == "fake-session-token-123"

        # Reading again should use the cache without calling request() again
        mock_req.reset_mock()
        token2 = rcx.get_session_token(force_refresh=False)
        assert token2 == "fake-session-token-123"
        mock_req.assert_not_called()
