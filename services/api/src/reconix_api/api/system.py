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
    return Health(status="OK")


@router.get("/operator")
def read_operator(operator: CurrentOperator) -> Operator:
    return operator
