"""The one error shape: {"code": ..., "message": ..., "details": {...}}."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

logger = logging.getLogger(__name__)

STATUS_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "TOO_MANY_REQUESTS",
    503: "NOT_READY",
}


class ApiError(Exception):
    """Raise this from any layer to return a clean error to the caller."""

    def __init__(
        self, status: int, code: str, message: str, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}


def error_response(
    status: int, code: str, message: str, details: dict[str, Any] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"code": code, "message": message, "details": details or {}}
    )


async def _api_error(_: Request, error: ApiError) -> JSONResponse:
    return error_response(error.status, error.code, error.message, error.details)


async def _http_error(_: Request, error: HTTPException) -> JSONResponse:
    code = STATUS_CODES.get(error.status_code, "HTTP_ERROR")
    return error_response(error.status_code, code, str(error.detail))


async def _validation_error(_: Request, error: RequestValidationError) -> JSONResponse:
    # Only field locations and messages: never echo the submitted values back.
    fields = [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in error.errors()]
    return error_response(422, "VALIDATION_ERROR", "The request is not valid.", {"fields": fields})


async def _unexpected_error(_: Request, error: Exception) -> JSONResponse:
    logger.exception("Unexpected error", exc_info=error)
    return error_response(500, "INTERNAL_ERROR", "Something went wrong on the server.")


def add_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(HTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unexpected_error)
