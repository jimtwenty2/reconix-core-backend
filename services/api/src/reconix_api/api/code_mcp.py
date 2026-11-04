"""The core MCP server at /mcp: the code scan tools, as thin wrappers over the same services
as the REST routes, with the same session token (Authorization: Bearer <token>).

The code upload itself stays REST (PUT /api/v1/sessions/{id}/code): MCP carries no binary.
"""

import asyncio
import functools
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from uuid import UUID

from fastapi import FastAPI
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import SecretStr, ValidationError
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from reconix_api.core import code_files
from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import get_session_factory
from reconix_api.core.errors import ApiError, error_response
from reconix_api.core.interfaces import Operator, ToolName
from reconix_api.models.enums import AgentRunStatus
from reconix_api.schemas.code import (
    CodeClonedOut,
    CodeCloneIn,
    CodeFileIn,
    CodeFindingOut,
    CodeScanIn,
    CodeScanOut,
    CodeSyncOut,
    CodeUploadOut,
)
from reconix_api.services import code, code_scans

logger = logging.getLogger(__name__)

PATH = "/mcp"
POLL_SECONDS = 1.0  # watch_code_scan reads the scan this often
HEARTBEAT_SECONDS = 10.0  # and reports at least this often, so the client never times out
# A sync of MAX_FILES entries with long paths is larger than the SDK's 4 MB default.
MAX_BODY_BYTES = code_files.MAX_FILES * (code_files.MAX_PATH + 200)


def add_code_mcp(app: FastAPI) -> MCPServer:
    """Adds the /mcp route to the app. The app's lifespan must run the returned server's
    session_manager."""
    # The SDK sets up root logging at this level when nothing else did; at its default
    # INFO, every library's request lines would reach the console.
    server = MCPServer("reconix-core", log_level="WARNING")
    _add_tools(server, app)
    transport = server.streamable_http_app(max_request_body_size=MAX_BODY_BYTES).routes[0]
    # Appended to the app's own routes (not mounted at "/"), so the Host check, CORS and
    # the error shape still apply and every REST route stays as it is.
    app.router.routes.append(Route(PATH, endpoint=_TokenGate(app, transport.endpoint)))
    return server


class _TokenGate:
    """401 before the MCP transport sees a request without a valid session token."""

    def __init__(self, app: FastAPI, transport: ASGIApp) -> None:
        self.app = app
        self.transport = transport

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            operator_of(self.app, Request(scope).headers)
        except ApiError as error:
            await error_response(error.status, error.code, error.message)(scope, receive, send)
            return
        await self.transport(scope, receive, send)


def operator_of(app: FastAPI, headers: Mapping[str, str]) -> Operator:
    """The session token's operator, like CurrentOperator does for REST. 401 UNAUTHORIZED."""
    scheme, _, token = headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "UNAUTHORIZED", "Send the session token as a Bearer token.")
    try:
        return app.state.interfaces.get_operator(token.strip())
    except PermissionError as error:
        raise ApiError(401, "UNAUTHORIZED", "The session token is not valid.") from error


def _tool(server: MCPServer) -> Callable[[Callable[..., Awaitable[Any]]], Any]:
    """Registers a tool. An ApiError reaches the client as "CODE: message"; anything else
    only as "internal error", so no value from inside the server leaks."""

    def register(fn: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(fn)
        async def run(*args: Any, **kwargs: Any) -> Any:
            try:
                return await fn(*args, **kwargs)
            except ApiError as error:
                raise ToolError(f"{error.code}: {error.message}") from None
            except ValidationError as error:
                # Field names only, never the values (a token could be one of them).
                fields = ", ".join(sorted({".".join(map(str, e["loc"])) for e in error.errors()}))
                raise ToolError(
                    f"VALIDATION_ERROR: These fields are not valid: {fields}."
                ) from None
            except Exception:
                logger.exception("MCP tool %s failed", fn.__name__)
                raise ToolError("internal error") from None

        return server.tool()(run)

    return register


def _add_tools(server: MCPServer, app: FastAPI) -> None:
    tool = _tool(server)

    def settings() -> Settings:
        return app.dependency_overrides.get(get_settings, get_settings)()

    def session_factory() -> sessionmaker[Session]:
        return app.dependency_overrides.get(get_session_factory, get_session_factory)()

    async def in_thread(fn: Callable[..., Any], *args: Any) -> Any:
        """fn(db, *args) in a worker thread, with its own database session."""

        def run() -> Any:
            with session_factory()() as db:
                return fn(db, *args)

        return await asyncio.to_thread(run)

    async def own_scan(ctx: Context, scan_id: UUID) -> None:
        operator = operator_of(app, ctx.headers or {})
        await in_thread(code_scans.ensure_own_scan, operator, scan_id)

    @tool
    async def sync_code(ctx: Context, session_id: UUID, files: list[CodeFileIn]) -> CodeSyncOut:
        """Tells core which files the workspace has (path, size_bytes, sha256). Deletes stored
        files not in the list and returns the ones to upload next, as one tar.gz to
        PUT /api/v1/sessions/{session_id}/code."""
        operator = operator_of(app, ctx.headers or {})
        write_audit = app.state.interfaces.write_audit
        return await in_thread(code.sync_code, write_audit, settings(), operator, session_id, files)

    @tool
    async def clone_repo(
        ctx: Context, session_id: UUID, url: str, token: str | None = None
    ) -> CodeClonedOut:
        """Replaces the session's code with a GitHub repo (https://github.com/<owner>/<repo>).
        A clone of it on this computer is copied; otherwise git clones it. token: a GitHub
        token for a private repo, used for this clone only and never stored."""
        operator = operator_of(app, ctx.headers or {})
        body = CodeCloneIn(url=url, token=SecretStr(token) if token else None)
        write_audit = app.state.interfaces.write_audit
        return await in_thread(
            code.clone_repo, write_audit, settings(), operator, session_id, body.url, body.token
        )

    @tool
    async def copy_folder(ctx: Context, session_id: UUID, path: str) -> CodeUploadOut:
        """Replaces the session's code with a copy of an absolute folder path on this
        computer. Secret folders (~/.ssh, ~/.aws, ...) and system folders are refused."""
        operator = operator_of(app, ctx.headers or {})
        write_audit = app.state.interfaces.write_audit
        return await in_thread(
            code.copy_folder, write_audit, settings(), operator, session_id, path
        )

    @tool
    async def start_code_scan(
        ctx: Context,
        session_id: UUID,
        paths: list[str] | None = None,
        tools: list[ToolName] | None = None,
        analyze: bool = True,
    ) -> CodeScanOut:
        """Starts a scan of the session's code and returns at once; follow it with
        watch_code_scan. paths: relative files or folders to scan (default: all). tools: some
        of SEMGREP, GITLEAKS, TRIVY, GRYPE, OSV_SCANNER, SYFT, SONAR_SCAN (default: all).
        analyze: the AI reviews each new finding. A rescan reads only what changed."""
        operator = operator_of(app, ctx.headers or {})
        body = CodeScanIn(paths=paths or [], tools=tools, analyze=analyze)
        interfaces = app.state.interfaces
        factory = session_factory()
        with factory() as db:
            assessment_id = await asyncio.to_thread(
                code_scans.session_assessment,
                db,
                interfaces,
                settings(),
                operator,
                session_id,
                body.tools,
            )
            return await code_scans.start_scan(
                db,
                factory,
                interfaces,
                app.state.mask_secrets,
                settings(),
                operator,
                assessment_id,
                body,
            )

    @tool
    async def get_code_scan(ctx: Context, scan_id: UUID) -> CodeScanOut:
        """A code scan's status, stage, progress, counts per severity and notes."""
        await own_scan(ctx, scan_id)
        return await in_thread(code_scans.read_scan, scan_id)

    @tool
    async def watch_code_scan(ctx: Context, scan_id: UUID) -> CodeScanOut:
        """Sends progress notifications until the scan ends, then returns the scan."""
        await own_scan(ctx, scan_id)
        last: tuple[Any, ...] | None = None
        reported = 0.0
        while True:
            scan = await in_thread(code_scans.read_scan, scan_id)
            now = asyncio.get_running_loop().time()
            state = (scan.stage, scan.progress, len(scan.notes))
            if state != last or now - reported >= HEARTBEAT_SECONDS:
                await ctx.report_progress(scan.progress, 100, _progress_message(scan))
                last, reported = state, now
            if scan.agent_runs_status != AgentRunStatus.RUNNING:
                return scan
            await asyncio.sleep(POLL_SECONDS)

    @tool
    async def cancel_code_scan(ctx: Context, scan_id: UUID) -> CodeScanOut:
        """Cancels a running scan; it stops before its next step."""
        await own_scan(ctx, scan_id)
        operator = operator_of(app, ctx.headers or {})
        return await in_thread(code_scans.cancel_scan, app.state.interfaces, operator, scan_id)

    @tool
    async def list_code_findings(
        ctx: Context, scan_id: UUID, include_false_positives: bool = True
    ) -> list[CodeFindingOut]:
        """The scan's findings with path, line, rule, masked snippet and the AI verdict
        (CONFIRMED, LIKELY_TRUE_POSITIVE, LIKELY_FALSE_POSITIVE or UNVERIFIED)."""
        await own_scan(ctx, scan_id)
        mask = app.state.mask_secrets
        return await in_thread(
            code_scans.list_scan_findings, settings(), mask, scan_id, include_false_positives
        )

    @tool
    async def get_code_scan_log(ctx: Context, scan_id: UUID, tool: str) -> str:
        """The masked output of one tool's run in the scan, e.g. SONAR_SCAN's log with the
        SonarQube dashboard link."""
        await own_scan(ctx, scan_id)
        return await in_thread(code_scans.scan_log, scan_id, tool)


def _progress_message(scan: CodeScanOut) -> str:
    """e.g. "SCANNING 40%" or "DONE 100% (SYFT 12 packages)"."""
    message = f"{scan.stage} {scan.progress}%"
    return f"{message} ({scan.notes[-1]})" if scan.notes else message
