"""The MCP tool wrapper: which error text reaches the client."""

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field

from reconix_api.api.code_mcp import _progress_message, _tool
from reconix_api.core.errors import ApiError
from reconix_api.schemas.code import CodeScanOut


class Body(BaseModel):
    token: str = Field(max_length=3)


def server_with(fn) -> MCPServer:
    server = MCPServer("test", log_level="WARNING")
    _tool(server)(fn)
    return server


async def test_an_api_error_reaches_the_client_as_code_and_message():
    async def refuse() -> str:
        raise ApiError(403, "NOT_YOUR_SCAN", "This code scan is of another session's code.")

    with pytest.raises(ToolError, match="NOT_YOUR_SCAN: This code scan is of another"):
        await server_with(refuse).call_tool("refuse", {})


async def test_a_validation_error_names_the_fields_never_the_values():
    async def check(token: str) -> str:
        return Body(token=token).token

    with pytest.raises(ToolError, match="VALIDATION_ERROR: .*token") as error:
        await server_with(check).call_tool("check", {"token": "secret-value"})
    assert "secret-value" not in str(error.value)


async def test_anything_else_is_only_an_internal_error(caplog):
    async def crash() -> str:
        raise RuntimeError("password=hunter2")

    with pytest.raises(ToolError) as error:
        await server_with(crash).call_tool("crash", {})
    assert str(error.value).endswith("internal error")
    assert "hunter2" not in str(error.value)


def test_the_progress_message_has_the_stage_and_the_last_note():
    scan = CodeScanOut.model_construct(stage="SCANNING", progress=40, notes=[])
    assert _progress_message(scan) == "SCANNING 40%"
    done = scan.model_copy(update={"stage": "DONE", "progress": 100, "notes": ["SYFT 2 packages"]})
    assert _progress_message(done) == "DONE 100% (SYFT 2 packages)"
