"""Command check: the third of the 5 checks.

Only the 5 tools are allowed, and no shell characters may appear in the target
or the arguments. Arguments are always a list, never one shell string.

Every argument must be an option from that tool's allowlist, or the value of
the option just before it. Anything else is blocked, so an argument can never
add a target, read a target list, write a file or load a script from a path.

Draft: the allowlist is written here until tool_specs.json in
Reconix-Kali-MCP lists each tool's options. Keep it in step with the option
rows in risk.py.
"""

import re
from collections.abc import Sequence

from reconix_ai.harness.checks.result import ALLOWED, CheckOutcome, blocked

KNOWN_TOOLS = {"NMAP", "NUCLEI", "ZAP", "SEMGREP", "GITLEAKS"}
SHELL_CHARACTERS = set(";|&$`<>\n\r\x00")

# What a value must look like. None means the option takes no value.
PORTS = r"[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*"
NUMBER = r"[0-9]{1,5}"
NAMES = r"[a-z0-9][a-z0-9_-]*(,[a-z0-9][a-z0-9_-]*)*"
NUCLEI_SEVERITY = r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*"
SEMGREP_CONFIG = r"auto|p/[a-z0-9][a-z0-9_-]*"
# A commit, a branch or a range like "main..HEAD". It may not start with "-".
GIT_RANGE = r"[A-Za-z0-9_/~^][A-Za-z0-9._/~^-]*(\.\.\.?[A-Za-z0-9_/~^][A-Za-z0-9._/~^-]*)?"

ALLOWED_OPTIONS: dict[str, dict[str, str | None]] = {
    "NMAP": {
        "-p": PORTS,
        "--top-ports": NUMBER,
        "-F": None,
        "-Pn": None,
        "-n": None,
        "-sT": None,
        "-sS": None,
        "-sV": None,
        "-sC": None,
        "-sU": None,
        "-O": None,
        "-A": None,
        "-T0": None,
        "-T1": None,
        "-T2": None,
        "-T3": None,
        "-T4": None,
        "-T5": None,
        "--script": NAMES,  # script names only, never a path
    },
    "NUCLEI": {
        "-severity": NUCLEI_SEVERITY,
        "-tags": NAMES,
        "-exclude-tags": NAMES,
        "-rate-limit": NUMBER,
        "-timeout": NUMBER,
        "-retries": NUMBER,
    },
    "ZAP": {},
    "SEMGREP": {"--config": SEMGREP_CONFIG},
    "GITLEAKS": {"--log-opts": GIT_RANGE},
}

# nmap scripts that reach hosts outside the target or are meant to break things.
BLOCKED_SCRIPTS = {"all", "broadcast", "dos", "external"}
BLOCKED_SCRIPT_PREFIXES = ("broadcast-", "targets-")
# nuclei templates that try to knock a service over or flood it with fuzzing requests.
BLOCKED_NUCLEI_TAGS = {"dos", "fuzz", "fuzzing"}
MAX_PORT = 65535
# Lowest and highest number an option may take. nuclei reads a rate limit of 0
# as "no limit"; 150 is its own default.
NUMBER_RANGES = {
    "-rate-limit": (1, 150),
    "-retries": (0, 5),
    "-timeout": (1, 60),
    "--top-ports": (1, MAX_PORT),
}


def check_command(tool: str, target: str, arguments: Sequence[str]) -> CheckOutcome:
    if tool.upper() not in KNOWN_TOOLS:
        return blocked("UNKNOWN_TOOL")
    if isinstance(arguments, str):
        return blocked("ARGUMENTS_NOT_A_LIST")
    if any(has_shell_characters(part) for part in [target, *arguments]):
        return blocked("SHELL_CHARACTERS")
    return check_options(ALLOWED_OPTIONS[tool.upper()], arguments)


def has_shell_characters(text: str) -> bool:
    return not SHELL_CHARACTERS.isdisjoint(text)


def check_options(allowed: dict[str, str | None], arguments: Sequence[str]) -> CheckOutcome:
    index = 0
    while index < len(arguments):
        # "--script=vuln" is the same as "--script vuln".
        option, equals, value = arguments[index].partition("=")
        if option not in allowed:
            return blocked("OPTION_NOT_ALLOWED")
        pattern = allowed[option]
        if pattern is None:
            if equals:
                return blocked("OPTION_VALUE_NOT_ALLOWED")
        else:
            if not equals:
                index += 1
                if index == len(arguments):
                    return blocked("OPTION_VALUE_NOT_ALLOWED")
                value = arguments[index]
            if not is_allowed_value(option, pattern, value):
                return blocked("OPTION_VALUE_NOT_ALLOWED")
        index += 1
    return ALLOWED


def is_allowed_value(option: str, pattern: str, value: str) -> bool:
    if re.fullmatch(pattern, value) is None:
        return False
    if option == "--script":
        return not any(is_blocked_script(name) for name in value.split(","))
    if option == "-tags":
        return BLOCKED_NUCLEI_TAGS.isdisjoint(value.split(","))
    if option == "-p":
        return all(int(port) <= MAX_PORT for port in re.findall(r"[0-9]+", value))
    if option in NUMBER_RANGES:
        low, high = NUMBER_RANGES[option]
        return low <= int(value) <= high
    return True


def is_blocked_script(name: str) -> bool:
    return name in BLOCKED_SCRIPTS or name.startswith(BLOCKED_SCRIPT_PREFIXES)
