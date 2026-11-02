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
    """Returns OK whenever the API is running. This is one of the few routes that work without a
    session token."""
    return Health(status="OK")


@router.get("/operator")
def read_operator(operator: CurrentOperator) -> Operator:
    """Tells you who the session token belongs to: its session id and the name of the person using
    it."""
    return operator
