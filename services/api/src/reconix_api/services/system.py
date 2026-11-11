"""System status: the Kali MCP container's reachability, for an indicator in the apps."""

from datetime import UTC, datetime
from urllib.parse import urlsplit

from reconix_api.clients import mcp
from reconix_api.core.config import Settings
from reconix_api.schemas.system import KaliStatus


async def kali_status(settings: Settings) -> KaliStatus:
    """Probes the Kali MCP server with the initialize handshake. No tool runs; the result
    is only whether it answered."""
    connected = await mcp.check_kali(
        settings.kali_mcp_url, settings.mcp_auth_token.get_secret_value()
    )
    return KaliStatus(connected=connected, host=_host(settings.kali_mcp_url), checked_at=_now())


def _host(url: str) -> str | None:
    """The host (and port) of the MCP URL, without the scheme, path or any credentials."""
    return urlsplit(url).netloc or None


def _now() -> datetime:
    return datetime.now(UTC)
