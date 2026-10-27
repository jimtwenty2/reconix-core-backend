"""API entry point."""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from reconix_api.api import system
from reconix_api.core.config import Settings, get_settings
from reconix_api.core.errors import add_error_handlers
from reconix_api.core.interfaces import Interfaces
from reconix_api.core.security import HostCheckMiddleware
from reconix_api.core.wiring import build_interfaces


def create_app(interfaces: Interfaces, settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="Reconix API", version="0.0.0")
    app.state.interfaces = interfaces

    # Added last = runs first: the Host check wraps everything, CORS included.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.web_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(HostCheckMiddleware, allowed_hosts=settings.allowed_hosts)
    add_error_handlers(app)

    app.include_router(system.router)
    return app


app = create_app(build_interfaces())


def run() -> None:
    settings = get_settings()
    uvicorn.run("reconix_api.main:app", host=settings.host, port=settings.port)


if __name__ == "__main__":
    run()
