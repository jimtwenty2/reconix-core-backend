"""Health check and who is calling."""

from fastapi import APIRouter
from pydantic import BaseModel

from reconix_api.core.interfaces import Operator
from reconix_api.core.security import CurrentOperator

router = APIRouter(tags=["system"])


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
