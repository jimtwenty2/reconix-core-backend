from pydantic import SecretStr

from reconix_api.core.config import Settings
from reconix_api.services import system


async def test_kali_status_reports_connected_and_host(monkeypatch):
    async def fake_check(url: str, token: str, *args, **kwargs) -> bool:
        assert url == "http://kali:8096/mcp"
        assert token == "tok"  # the secret is passed in, never returned
        return True

    monkeypatch.setattr(system.mcp, "check_kali", fake_check)
    out = await system.kali_status(
        Settings(kali_mcp_url="http://kali:8096/mcp", mcp_auth_token=SecretStr("tok"))
    )
    assert out.connected is True
    assert out.host == "kali:8096"  # host only, no scheme, path or token
    assert out.checked_at is not None


async def test_kali_status_unreachable_and_no_host_when_url_unset(monkeypatch):
    async def fake_check(*args, **kwargs) -> bool:
        return False

    monkeypatch.setattr(system.mcp, "check_kali", fake_check)
    out = await system.kali_status(Settings(kali_mcp_url=""))
    assert out.connected is False
    assert out.host is None
