"""API entry point."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
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
    chat,
    code,
    code_scans,
    evidence,
    findings,
    knowledge,
    knowledge_add_ons,
    llm_providers,
    messages,
    plans,
    reports,
    scopes,
    sessions,
    stream,
    system,
    terminal,
    timeline,
    vscode_chat,
)
from reconix_api.core.agent import prepare_checkpoints
from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import get_session_factory
from reconix_api.core.errors import add_error_handlers
from reconix_api.core.finding_memory import FindingMemory, ai_finding_memory
from reconix_api.core.interfaces import Interfaces
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from reconix_api.core.live_events import LiveEvents
from reconix_api.core.masking import MaskSecrets
from reconix_api.core.rate_limit import RateLimitMiddleware
from reconix_api.core.security import HostCheckMiddleware
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.core.wiring import build_interfaces, build_mask_secrets

API_PREFIX = "/api/v1"  # every route lives under it

# Shown at the top of Swagger (/docs).
API_DESCRIPTION = """\
This is the local API of Reconix Core. It runs only on this computer (127.0.0.1), and the
terminal app, the local web and the VS Code extension all talk to it.

**How a test goes.** You write a scope, the agent plans the test and suggests each step, a
person approves the steps that need it, the tools run, and the results become findings, an
analysis and finally a report you can download.

**Signing in.** Call `POST /api/v1/sessions` to get a session token. It is shown only once, so
keep it. Send it on every other call as `Authorization: Bearer <token>`; in this page, use the
**Authorize** button. Only `GET /health`, `POST /sessions` and `POST /sessions/web-sign-in`
work without a token.

**The AI suggests, the API decides.** The agent never runs a tool itself. Every action it
suggests is checked first: its input, its scope, its command, its risk and whether it repeats
itself. A `LOW` risk action runs right away. A `MEDIUM` or `HIGH` one waits until a person
approves it. Anything riskier than the scope allows is `BLOCKED` with a 422. An approval
expires after 30 minutes and can be used only once.

**Terminal.** `WS /api/v1/terminal` opens the terminal app for the web Terminal page (WebSockets
are not listed below). Send the token as the subprotocol `token.<token>` next to
`reconix.terminal`; only the local web's Origin is accepted, and one terminal per session.

**Errors.** Every error has the same shape:
`{"code": "UPPER_CASE", "message": "...", "details": {...}}`. Secrets are masked in every
answer the API gives. Each session token may send a set number of requests a minute (signing
in has a smaller limit); after that the API answers 429 TOO_MANY_REQUESTS with a Retry-After
header.
"""

# One entry per router tag, in the order of the main flow; Swagger lists them in this order.
API_TAGS = [
    {
        "name": "system",
        "description": "Check that the API is running, and see who a session token belongs to.",
    },
    {
        "name": "sessions",
        "description": "Open, read and close sessions, and sign in to the local web with a code.",
    },
    {
        "name": "messages",
        "description": "Chat with the agent. Every message is saved in its session.",
    },
    {
        "name": "code",
        "description": "Send a workspace's source code to a session so it can be scanned.",
    },
    {
        "name": "scope manifests",
        "description": "Write down what may be tested, edit it, and submit it for approval.",
    },
    {
        "name": "assessments",
        "description": "The tests created when a scope is submitted, with their overview "
        "and timeline.",
    },
    {
        "name": "plans",
        "description": "Ask the agent to plan the test and to suggest the next step.",
    },
    {
        "name": "agent runs",
        "description": "Follow one job of the agent, such as a plan or a suggested step.",
    },
    {
        "name": "actions",
        "description": "The tool steps. Each one is checked, approved when needed, and then run.",
    },
    {
        "name": "approvals",
        "description": "Everything that waits for a person to approve or reject it.",
    },
    {
        "name": "code scans",
        "description": "Scan the code sent to a session with SEMGREP and GITLEAKS.",
    },
    {
        "name": "findings",
        "description": "The problems the tools found. Review them and record your own checks.",
    },
    {
        "name": "evidence",
        "description": "The proof behind a finding, with any secret already masked.",
    },
    {
        "name": "analysis",
        "description": "Ask the agent what it thinks about the findings that are still open.",
    },
    {
        "name": "reports",
        "description": "Create report versions, ask for their review, and download them.",
    },
    {
        "name": "llm providers",
        "description": "Choose which AI model Reconix uses. Only one provider is active at a time.",
    },
    {
        "name": "knowledge add-ons",
        "description": "Add your own files to the knowledge search, and search it together "
        "with CVE, CWE, OWASP, ATT&CK and the tool guides.",
    },
    {
        "name": "stream",
        "description": "Get every audit event live, as Server-Sent Events.",
    },
]


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

    app = FastAPI(
        title="Reconix API",
        version="0.0.0",
        description=API_DESCRIPTION,
        openapi_tags=API_TAGS,
        lifespan=lifespan,
    )
    # Every audit event also goes to GET /stream, once its line is written.
    app.state.live_events = LiveEvents()
    app.state.interfaces = replace(
        interfaces, write_audit=app.state.live_events.publishing(interfaces.write_audit)
    )
    app.state.session_tokens = session_tokens or SessionTokens()
    app.state.mask_secrets = mask_secrets or build_mask_secrets()
    app.state.knowledge_store = knowledge_store or KnowledgeStore()
    app.state.finding_memory = finding_memory or ai_finding_memory

    # Added last = runs first: the Host check, then CORS, then the rate limit. CORS wraps the
    # rate limit so the local web can read a 429 and its Retry-After.
    app.add_middleware(
        RateLimitMiddleware,
        per_minute=settings.rate_limit_per_minute,
        sign_in_per_minute=settings.sign_in_limit_per_minute,
        web_origins=settings.web_origins,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.web_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )
    app.add_middleware(HostCheckMiddleware, allowed_hosts=settings.allowed_hosts)
    add_error_handlers(app)

    routers = [
        system,
        sessions,
        code,
        code_scans,
        messages,
        chat,
        vscode_chat,
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
        knowledge,
        timeline,
        stream,
        terminal,
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
    # ws_max_size: the terminal takes at most 64 KiB of keys a message, so never buffer more.
    uvicorn.run("reconix_api.main:app", host=settings.host, port=settings.port, ws_max_size=131072)


if __name__ == "__main__":
    run()
