"""Health check, who is calling, and the Kali MCP container's reachability."""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.interfaces import Operator
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.system import KaliStatus
from reconix_api.services import system

router = APIRouter(tags=["system"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


class Health(BaseModel):
    status: str


@router.get("/health")
def health() -> Health:
    """Returns OK while the API is running.

    Security:
    - Open. Works without a session token.
    """
    return Health(status="OK")


@router.get("/operator")
def read_operator(operator: CurrentOperator) -> Operator:
    """Returns the owner of the session token: its session id and the person's name.

    Security:
    - Requires a valid session token.
    """
    return operator


@router.get("/system/kali")
async def read_kali_status(_: CurrentOperator, settings: CurrentSettings) -> KaliStatus:
    """Returns whether the Kali MCP tool container is reachable, for a status indicator.

    Business Rules:
    - Probes the Kali MCP server with the initialize handshake only; no tool runs.
    - An unreachable, mis-authenticated or unconfigured server answers connected=false,
      never an error.

    Security:
    - Requires a valid session token.
    - Never returns the Kali access token; only the configured host.
    """
    return await system.kali_status(settings)
