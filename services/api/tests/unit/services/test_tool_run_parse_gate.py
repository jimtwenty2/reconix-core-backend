"""The parse gate: which tool runs get their output read for findings.

Most tools must COMPLETE. The few that EXIT NON-ZERO when they find issues
(schemathesis, sqlmap, dalfox) are still parsed when they came back FAILED/TIMED_OUT
but left output to read, so their findings are not lost.
"""

from dataclasses import dataclass

from reconix_api.models.enums import ToolRunStatus
from reconix_api.services.tool_runs import FINDINGS_ON_NONZERO_EXIT, _should_parse


@dataclass
class _Run:
    tool_run_status: ToolRunStatus
    output_masked: str | None


@dataclass
class _Action:
    tool: str


def test_completed_run_is_parsed() -> None:
    assert _should_parse(_Run(ToolRunStatus.COMPLETED, "out"), _Action("NMAP")) is True


def test_failed_find_on_nonzero_tool_with_output_is_parsed() -> None:
    # schemathesis exits 1 when it finds bugs; its output still holds the findings.
    assert _should_parse(_Run(ToolRunStatus.FAILED, "...failures..."), _Action("SCHEMATHESIS"))
    assert _should_parse(_Run(ToolRunStatus.FAILED, "x"), _Action("sqlmap"))
    assert _should_parse(_Run(ToolRunStatus.TIMED_OUT, "x"), _Action("DALFOX"))


def test_failed_find_on_nonzero_tool_with_no_output_is_not_parsed() -> None:
    assert _should_parse(_Run(ToolRunStatus.FAILED, ""), _Action("SCHEMATHESIS")) is False
    assert _should_parse(_Run(ToolRunStatus.FAILED, None), _Action("SCHEMATHESIS")) is False


def test_failed_ordinary_tool_is_not_parsed() -> None:
    # nmap failing is a real failure; there are no findings to salvage.
    assert _should_parse(_Run(ToolRunStatus.FAILED, "half xml"), _Action("NMAP")) is False


def test_the_set_holds_only_find_on_nonzero_tools() -> None:
    assert FINDINGS_ON_NONZERO_EXIT == {"schemathesis", "sqlmap", "dalfox"}
