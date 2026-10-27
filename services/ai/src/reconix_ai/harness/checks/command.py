"""Command check: the third of the 5 checks.

Only the 5 tools are allowed, and no shell characters may appear in the target
or the arguments. Arguments are always a list, never one shell string.

Not done yet: each tool's list of allowed options. It comes from
tool_specs.json in Reconix-Kali-MCP once that file lists them. Until then the
risk check treats every option it does not know as HIGH.
"""

from collections.abc import Sequence

from reconix_ai.harness.checks.result import ALLOWED, CheckOutcome, blocked

KNOWN_TOOLS = {"NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS"}
SHELL_CHARACTERS = set(";|&$`<>\n\r\x00")


def check_command(tool: str, target: str, arguments: Sequence[str]) -> CheckOutcome:
    if tool.upper() not in KNOWN_TOOLS:
        return blocked("UNKNOWN_TOOL")
    if isinstance(arguments, str):
        return blocked("ARGUMENTS_NOT_A_LIST")
    if any(has_shell_characters(part) for part in [target, *arguments]):
        return blocked("SHELL_CHARACTERS")
    return ALLOWED


def has_shell_characters(text: str) -> bool:
    return not SHELL_CHARACTERS.isdisjoint(text)
