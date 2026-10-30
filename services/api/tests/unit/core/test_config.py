import pytest
from pydantic import ValidationError

from reconix_api.core.config import Settings


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_hosts_are_allowed(host):
    assert Settings(host=host).host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])  # noqa: S104
def test_api_never_listens_outside_this_computer(host):
    with pytest.raises(ValidationError):
        Settings(host=host)


def test_kali_mcp_url_reads_the_new_name_first(monkeypatch):
    monkeypatch.setenv("RECONIX_KALI_MCP_URL", "http://127.0.0.1:8766/mcp")
    monkeypatch.setenv("RECONIX_MCP_URL", "http://127.0.0.1:9999/mcp")
    assert Settings(_env_file=None).kali_mcp_url == "http://127.0.0.1:8766/mcp"


def test_kali_mcp_url_still_reads_the_old_name(monkeypatch):
    """An old .env must not fall back to the default port and send the access key there."""
    monkeypatch.delenv("RECONIX_KALI_MCP_URL", raising=False)
    monkeypatch.setenv("RECONIX_MCP_URL", "http://127.0.0.1:8766/mcp")
    assert Settings(_env_file=None).kali_mcp_url == "http://127.0.0.1:8766/mcp"
