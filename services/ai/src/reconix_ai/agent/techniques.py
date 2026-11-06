"""The techniques a plan covers, per assessment type, read from prompts/techniques.md.

The methodology is plain Markdown so a person changes it by pull request. This module
picks the sections for the scope (web and api for URL targets, network for IPs and
domains, or the type the person named in the chat) and shows each step form only when
the harness would allow it on this scope. A step the harness would block, or a tool
outside the scope's tools, is listed as "not possible here", so the model never plans
it; a manual technique is listed for a person and never planned.

This text only guides the model. Every step it suggests still goes through check()
twice (rule S2), exactly as before.
"""

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from reconix_ai.agent.state import AgentScope, scope_from_dict
from reconix_ai.harness import check
from reconix_ai.harness.checks.result import Decision

TECHNIQUES_FILE = Path(__file__).resolve().parents[1] / "prompts" / "techniques.md"
TYPES = ("web", "api", "network")
TYPE_TITLES = {"web": "Web application", "api": "API", "network": "Network"}
MODES = ("auto", "partial", "manual")
# The type the person (or the Reconix app) names in the chat: "Assessment type: API".
ASSESSMENT_TYPE = re.compile(
    r"assessment type:\s*(web url|web|api|network|source code|source)\b", re.IGNORECASE
)
CHAT_TYPES = {
    "web url": ["web"],
    "web": ["web"],
    "api": ["api"],
    "network": ["network"],
    "source code": [],
    "source": [],
}
PLACEHOLDER = re.compile(r"\{(url|host|schema|ports)\}")
# Tools that only make sense on an https:// URL: their {url} is the scope's https prefix.
HTTPS_ONLY = {"TESTSSL"}
# What {ports} stands for while checking a step on a scope that lists no ports.
ANY_PORTS = "80,443"
PLACEHOLDERS_TEXT = (
    "In the step forms, {url} is an allowed URL prefix, {host} an allowed IP, range or "
    "domain, {schema} the URL of the API's OpenAPI document inside the scope, and {ports} "
    "the scope's allowed ports. Split each option and value into its own argument."
)


@dataclass(frozen=True)
class Technique:
    key: str
    name: str
    investigates: str
    tools: tuple[str, ...]  # catalog names, lowercase
    mode: str  # auto, partial or manual
    steps: tuple[str, ...]  # "TOOL target options", placeholders unfilled
    note: str


@dataclass(frozen=True)
class _Action:
    """The fields of the shared Action that check() reads."""

    tool: str
    target: str
    arguments: list[str]
    is_validation: bool = False


@dataclass(frozen=True)
class _Context:
    """A check context with no history: only scope, command and risk can block here."""

    scope: AgentScope
    now: datetime
    input_text: str | None = None
    recent_runs: tuple = ()
    runs_in_assessment: int = 0


@lru_cache(maxsize=1)
def methodology() -> dict[str, tuple[Technique, ...]]:
    """{type: its techniques, in the file's order}."""
    sections: dict[str, list[Technique]] = {}
    current: str | None = None
    for line in TECHNIQUES_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
        elif current and line.startswith("|") and not _is_header(line):
            sections[current].append(_technique(line))
    return {name: tuple(rows) for name, rows in sections.items()}


def _is_header(line: str) -> bool:
    cells = _cells(line)
    return cells[0] == "key" or set("".join(cells)) <= set("-: ")


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _technique(line: str) -> Technique:
    key, name, investigates, tools, mode, steps, note = _cells(line)
    return Technique(
        key=key,
        name=name,
        investigates=investigates,
        tools=tuple(tool.strip() for tool in tools.split(",") if tool.strip() not in ("", "-")),
        mode=mode,
        steps=tuple(step.strip() for step in steps.split(";") if step.strip() not in ("", "-")),
        note=note,
    )


def assessment_types(scope: dict[str, Any], messages: list[str]) -> list[str]:
    """The person's named type (the newest "Assessment type: ..." line), else by targets."""
    for message in reversed(messages):
        found = ASSESSMENT_TYPE.search(message)
        if found:
            return list(CHAT_TYPES[found.group(1).lower()])
    types: list[str] = []
    if scope.get("url_prefixes"):
        types += ["web", "api"]
    if scope.get("ip_ranges") or scope.get("domains"):
        types.append("network")
    return types


def split_step(step: str) -> tuple[str, str, list[str]]:
    tool, target, *arguments = step.split()
    return tool, target, arguments


def step_allowed(step: str, scope: AgentScope) -> bool:
    """True if the harness would allow this step form on this scope, filled with the
    scope's own first targets. The time window is left out: it says when, not what."""
    tool, target, arguments = split_step(step)
    values = sample_values(scope, https_only=tool.upper() in HTTPS_ONLY)
    try:
        filled = [_fill(part, values) for part in (target, *arguments)]
    except KeyError:
        return False  # the scope has no target of that kind
    action = _Action(tool=tool, target=filled[0], arguments=filled[1:])
    timeless = replace(scope, window_start=None, window_end=None)
    return check(action, _Context(scope=timeless, now=datetime.now(UTC))).decision == (
        Decision.ALLOW
    )


DOC_HINTS = (
    "/openapi.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
)


def looks_like_doc(url: str) -> bool:
    """Whether a scope URL is itself an OpenAPI/Swagger document, not an API root. Spring
    serves it at /v3/api-docs, Swagger at /swagger.json, etc. — not every API uses the
    /openapi.json default, so a doc URL in scope is used as-is."""
    low = url.lower().rstrip("/")
    return low.endswith(".json") or any(hint in low for hint in DOC_HINTS)


def sample_values(scope: AgentScope, https_only: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    urls = [url for url in scope.url_prefixes if not url.startswith("*.")]
    if https_only:
        urls = [url for url in urls if url.lower().startswith("https://")]
    if urls:
        # schemathesis needs the OpenAPI document: an in-scope URL that is already a doc
        # (e.g. /v3/api-docs) is used directly; otherwise fall back to <base>/openapi.json.
        # The base URL for crawling/scanning is the first non-doc URL.
        docs = [url for url in urls if looks_like_doc(url)]
        bases = [url for url in urls if not looks_like_doc(url)]
        values["url"] = (bases or urls)[0]
        values["schema"] = docs[0] if docs else urls[0].rstrip("/") + "/openapi.json"
    hosts = [host for host in [*scope.ip_ranges, *scope.domains] if not host.startswith("*.")]
    if hosts:
        values["host"] = hosts[0]
        # A network host has no URL prefix, but nuclei/testssl need a URL. Build one on the
        # host's first allowed web/TLS port, so those techniques are plannable on a network
        # scope (the harness allows a URL on an in-scope host whose port is allowed).
        if "url" not in values:
            web_port = next(
                (p for p in (80, 8080, 8000, 443, 8443) if p in scope.allowed_ports), None
            )
            if web_port is not None:
                scheme = "https" if web_port in (443, 8443) else "http"
                base = _strip_cidr(hosts[0])
                values["url"] = f"{scheme}://{base}:{web_port}/"
                values.setdefault("schema", values["url"].rstrip("/") + "/openapi.json")
    values["ports"] = ",".join(str(port) for port in scope.allowed_ports) or ANY_PORTS
    return values


def _strip_cidr(host: str) -> str:
    """A bare host for a URL: an IP range like "10.0.0.0/24" has no single URL host, so
    take its network address; a plain IP or domain is used as is."""
    if "/" in host:
        try:
            import ipaddress

            return str(ipaddress.ip_network(host, strict=False).network_address)
        except ValueError:
            return host.split("/", 1)[0]
    return host


def _fill(text: str, values: dict[str, str]) -> str:
    return PLACEHOLDER.sub(lambda match: values[match.group(1)], text)


def techniques_text(scope: dict[str, Any], messages: list[str]) -> str:
    """The prompt section for the plan, or "" when no methodology fits (a code scope)."""
    types = assessment_types(scope, messages)
    if not types:
        return ""
    rules = scope_from_dict(scope)
    parts = ["## Techniques to cover", PLACEHOLDERS_TEXT]
    for kind in types:
        parts.append(section_text(kind, methodology().get(kind, ()), rules))
    return "\n\n".join(parts)


def section_text(kind: str, techniques: tuple[Technique, ...], scope: AgentScope) -> str:
    lines = [f"### {TYPE_TITLES[kind]}"]
    not_possible: list[str] = []
    manual: list[str] = []
    for technique in techniques:
        label = f"{technique.name} ({technique.investigates})"
        if technique.mode == "manual":
            manual.append(label)
            continue
        steps = [step for step in technique.steps if step_allowed(step, scope)]
        if not steps:
            tools = ", ".join(technique.tools)
            not_possible.append(f"{technique.name} (needs {tools} on a target it allows)")
            continue
        partial = " Partial: a person finishes it." if technique.mode == "partial" else ""
        note = f" {technique.note}" if technique.note else ""
        lines.append(f"- {technique.key}: {label}. Steps: {'; '.join(steps)}.{partial}{note}")
    if len(lines) == 1:
        lines.append("- none can run with this scope's tools and targets")
    if not_possible:
        lines.append("Not possible with this scope (never plan these): " + "; ".join(not_possible))
    if manual:
        lines.append("A person checks these (never plan a tool step): " + "; ".join(manual))
    return "\n".join(lines)
