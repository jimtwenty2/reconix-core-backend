"""Command check: the third of the 5 checks.

A tool is allowed if it is in the Kali catalog (`tool_specs.json`); any other
tool is blocked. Arguments are always a list of strings, never one shell string.

Two character rules keep an argument from turning into something else:
- Control and format characters (newlines, null, zero-width spaces, bidi
  overrides) are blocked in the target and every argument, for every tool —
  they have no place in a real argument and only hide intent.
- Shell metacharacters (``; | & $ ` < >``) are blocked too, except for the
  free-shell tools (run_command, proxychains, msfconsole, smbclient), whose
  whole purpose is to run a real shell command. The risk check pins those to
  HIGH instead, so a person approves and types the target before any runs.

The per-tool option allowlist is gone: with the full catalog open, a risky
option is rated by `risk_ops.json` and sent for approval (see risk.py), not
refused here. The catalog + these character rules are what this check enforces;
scope, risk and approval do the rest.
"""

import unicodedata
from collections.abc import Sequence

from reconix_ai.harness.catalog import is_free_shell, is_known_tool
from reconix_ai.harness.checks.result import ALLOWED, CheckOutcome, blocked

SHELL_METACHARACTERS = set(";|&$`<>")


def check_command(tool: str, target: str, arguments: Sequence[str]) -> CheckOutcome:
    if not is_known_tool(tool):
        return blocked("UNKNOWN_TOOL")
    if isinstance(arguments, str):
        return blocked("ARGUMENTS_NOT_A_LIST")
    parts = [target, *arguments]
    if any(has_control_characters(part) for part in parts):
        return blocked("SHELL_CHARACTERS")
    if not is_free_shell(tool) and any(has_shell_metacharacters(part) for part in parts):
        return blocked("SHELL_CHARACTERS")
    return ALLOWED


def has_control_characters(text: str) -> bool:
    # Cc = control (newline, null, ...), Cf = format (zero-width, bidi overrides).
    return any(unicodedata.category(char) in ("Cc", "Cf") for char in text)


def has_shell_metacharacters(text: str) -> bool:
    return not SHELL_METACHARACTERS.isdisjoint(text)
