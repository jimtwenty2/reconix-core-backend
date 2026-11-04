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


def test_mcp_auth_token_reads_the_new_name_first(monkeypatch):
    monkeypatch.setenv("RECONIX_MCP_AUTH_TOKEN", "new-fake-token")
    monkeypatch.setenv("RECONIX_MCP_ACCESS_KEY", "old-fake-token")
    assert Settings(_env_file=None).mcp_access_key.get_secret_value() == "new-fake-token"


def test_mcp_auth_token_still_reads_the_old_name(monkeypatch):
    """An old .env with RECONIX_MCP_ACCESS_KEY keeps working until v1.0.0."""
    monkeypatch.delenv("RECONIX_MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("RECONIX_MCP_ACCESS_KEY", "old-fake-token")
    assert Settings(_env_file=None).mcp_access_key.get_secret_value() == "old-fake-token"


def test_provider_encryption_key_reads_the_new_name_first(monkeypatch):
    monkeypatch.setenv("RECONIX_PROVIDER_ENCRYPTION_KEY", "new-fake-key")
    monkeypatch.setenv("RECONIX_FERNET_KEY", "old-fake-key")
    assert Settings(_env_file=None).provider_encryption_key.get_secret_value() == "new-fake-key"


def test_provider_encryption_key_still_reads_the_old_name(monkeypatch):
    """An old .env with RECONIX_FERNET_KEY keeps reading the saved API keys until v1.0.0."""
    monkeypatch.delenv("RECONIX_PROVIDER_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("RECONIX_FERNET_KEY", "old-fake-key")
    assert Settings(_env_file=None).provider_encryption_key.get_secret_value() == "old-fake-key"


def test_provider_encryption_key_can_be_set_by_name_in_code():
    settings = Settings(_env_file=None, provider_encryption_key="fake-key")
    assert settings.provider_encryption_key.get_secret_value() == "fake-key"


def test_inside_its_container_the_api_may_listen_on_all_interfaces():
    # Compose publishes the port on 127.0.0.1 only, so this computer is still the only way in.
    assert Settings(_env_file=None, host="0.0.0.0", in_container=True).host == "0.0.0.0"  # noqa: S104


@pytest.mark.parametrize("host", ["192.168.1.10", "::"])
def test_inside_its_container_no_other_address_is_allowed(host):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, host=host, in_container=True)
