"""API entry point."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from functools import partial

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from reconix_api.api import (
    actions,
    agent_runs,
    analysis,
    approvals,
    assessments,
    evidence,
    findings,
    knowledge_add_ons,
    llm_providers,
    messages,
    plans,
    reports,
    scopes,
    sessions,
    system,
)
from reconix_api.core.agent import prepare_checkpoints
from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import get_session_factory
from reconix_api.core.errors import add_error_handlers
from reconix_api.core.finding_memory import FindingMemory, ai_finding_memory
from reconix_api.core.interfaces import Interfaces
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from reconix_api.core.masking import MaskSecrets
from reconix_api.core.security import HostCheckMiddleware
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.core.wiring import build_interfaces, build_mask_secrets

API_PREFIX = "/api/v1"  # every route lives under it


def create_app(
    interfaces: Interfaces,
    settings: Settings | None = None,
    session_tokens: SessionTokens | None = None,
    mask_secrets: MaskSecrets | None = None,
    knowledge_store: KnowledgeStore | None = None,
    finding_memory: FindingMemory | None = None,
    startup: Callable[[], Awaitable[None]] | None = None,
) -> FastAPI:
    """startup runs once when the server starts, before any request is served."""
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if startup is not None:
            await startup()
        yield

    app = FastAPI(title="Reconix API", version="0.0.0", lifespan=lifespan)
    app.state.interfaces = interfaces
    app.state.session_tokens = session_tokens or SessionTokens()
    app.state.mask_secrets = mask_secrets or build_mask_secrets()
    app.state.knowledge_store = knowledge_store or KnowledgeStore()
    app.state.finding_memory = finding_memory or ai_finding_memory

    # Added last = runs first: the Host check wraps everything, CORS included.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.web_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(HostCheckMiddleware, allowed_hosts=settings.allowed_hosts)
    add_error_handlers(app)

    routers = [
        system,
        sessions,
        messages,
        scopes,
        assessments,
        actions,
        plans,
        analysis,
        agent_runs,
        reports,
        approvals,
        findings,
        evidence,
        llm_providers,
        knowledge_add_ons,
    ]
    for module in routers:
        app.include_router(module.router, prefix=API_PREFIX)
    return app


_session_tokens = SessionTokens()
_settings = get_settings()
app = create_app(
    build_interfaces(
        _session_tokens,
        get_session_factory(),
        _settings.audit_log_path,
        _settings.kali_mcp_url,
        _settings.mcp_access_key.get_secret_value(),
        _settings.database_url,
        _settings,
    ),
    session_tokens=_session_tokens,
    # The agent's checkpoint tables are made here, never inside a request.
    startup=partial(prepare_checkpoints, _settings.database_url),
)


def run() -> None:
    settings = get_settings()
    uvicorn.run("reconix_api.main:app", host=settings.host, port=settings.port)


if __name__ == "__main__":
    run()
