"""The methodology in prompts/techniques.md: it loads, every step form passes the
harness, and the plan sees only what the scope can run."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

from reconix_ai.agent.nodes import DEFAULT_GOAL
from reconix_ai.agent.prompts import plan_messages, reflect_messages
from reconix_ai.agent.techniques import (
    MODES,
    TYPES,
    assessment_types,
    methodology,
    sample_values,
    split_step,
    techniques_text,
)
from reconix_ai.harness import check
from reconix_ai.harness.catalog import is_destructive, is_known_tool
from reconix_ai.harness.checks.result import Decision, RiskLevel

# The shared technique map (TUI, AI and API use the same keys).
KEYS = {
    "web": [
        "fingerprint", "versions", "directories", "authentication", "authorization",
        "input_validation", "headers", "tls", "file_upload", "configuration",
    ],
    "api": [
        "endpoints", "authentication", "authorization", "rate_limit", "input_validation",
        "mass_assignment", "data_exposure", "http_methods", "cors", "schema_validation",
        "ssrf", "api_versions",
    ],
    "network": [
        "host_discovery", "port_scan", "services", "versions", "os_fingerprint",
        "cve_matching", "misconfiguration", "tls", "firewall", "segmentation",
    ],
}  # fmt: skip
URL = "https://juice-shop.lab:3000/"
HOST = "172.20.0.5"
VALUES = {"{url}": URL, "{host}": HOST, "{schema}": URL + "openapi.json"}
# Destructive tools are allowed in the methodology only as explicit confirm steps
# (validation phase, gated at HIGH, the operator types the target).
CONFIRM_TOOLS = {"sqlmap"}


@dataclass(frozen=True)
class Scope:
    allowed_tools: list[str]
    allowed_ports: list[int] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=lambda: ["172.20.0.0/24"])
    domains: list[str] = field(default_factory=list)
    url_prefixes: list[str] = field(default_factory=lambda: [URL])
    repo_paths: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    max_risk: str = "MEDIUM"
    window_start: datetime | None = None
    window_end: datetime | None = None


@dataclass(frozen=True)
class Action:
    tool: str
    target: str
    arguments: list[str]
    is_validation: bool = False


@dataclass(frozen=True)
class Context:
    scope: Scope
    now: datetime = datetime(2026, 11, 6, tzinfo=UTC)
    input_text: str | None = None
    recent_runs: tuple = ()
    runs_in_assessment: int = 0


def scope_dict(**changes: Any) -> dict[str, Any]:
    scope = {
        "ip_ranges": [],
        "domains": [],
        "url_prefixes": [],
        "repo_paths": [],
        "excluded_targets": [],
        "allowed_tools": [],
        "max_risk": "HIGH",
        "window_start": None,
        "window_end": None,
        "allowed_ports": [],
    }
    return scope | changes


def every_step() -> list[tuple[str, str, str]]:
    return [
        (kind, technique.key, step)
        for kind, techniques in methodology().items()
        for technique in techniques
        for step in technique.steps
    ]


def filled(step: str, ports: str) -> Action:
    tool, target, arguments = split_step(step)
    values = {**VALUES, "{ports}": ports}
    for name, value in values.items():
        target = target.replace(name, value)
        arguments = [argument.replace(name, value) for argument in arguments]
    return Action(tool=tool, target=target, arguments=arguments)


# --- the file -------------------------------------------------------------------------


def test_the_methodology_has_the_shared_techniques_in_order() -> None:
    loaded = methodology()

    assert tuple(loaded) == TYPES
    assert {kind: [t.key for t in techniques] for kind, techniques in loaded.items()} == KEYS


def test_manual_techniques_have_no_steps_and_the_others_do() -> None:
    for techniques in methodology().values():
        for technique in techniques:
            assert technique.mode in MODES
            if technique.mode == "manual":
                assert technique.steps == () and technique.tools == ()
            else:
                assert technique.steps, technique.key


@pytest.mark.parametrize(("kind", "key", "step"), every_step())
def test_every_step_uses_one_of_its_techniques_tools(kind: str, key: str, step: str) -> None:
    technique = next(t for t in methodology()[kind] if t.key == key)
    tool = split_step(step)[0]

    assert is_known_tool(tool)
    # No destructive tool may appear except an explicit confirm tool (e.g. sqlmap).
    assert not is_destructive(tool) or tool.lower() in CONFIRM_TOOLS
    assert tool.lower() in technique.tools


@pytest.mark.parametrize(("kind", "key", "step"), every_step())
def test_every_step_passes_the_harness(kind: str, key: str, step: str) -> None:
    """No option in the methodology may be one the harness blocks. A normal step needs at
    most MEDIUM (a person still approves MEDIUM); a confirm step (sqlmap) is HIGH and only
    allowed when the scope's max_risk is HIGH, where the operator approves it by target."""
    action = filled(step, ports="80,443")
    if is_destructive(action.tool):
        scope = Scope(allowed_tools=[action.tool], max_risk="HIGH")
        result = check(action, Context(scope=scope))
        assert result.decision == Decision.ALLOW, (step, result.blocked_by, result.reason)
        assert result.risk == RiskLevel.HIGH
    else:
        scope = Scope(allowed_tools=[action.tool])
        result = check(action, Context(scope=scope))
        assert result.decision == Decision.ALLOW, (step, result.blocked_by, result.reason)
        assert result.risk in (RiskLevel.LOW, RiskLevel.MEDIUM)


@pytest.mark.parametrize(
    "step", [step for _, _, step in every_step() if "{ports}" in step], ids=str
)
def test_port_steps_pass_a_scope_with_allowed_ports(step: str) -> None:
    action = filled(step, ports="22,80,443")
    scope = Scope(allowed_tools=[action.tool], allowed_ports=[22, 80, 443])

    assert check(action, Context(scope=scope)).decision == Decision.ALLOW


# --- which sections the plan sees -----------------------------------------------------


def test_url_targets_get_web_and_api_and_hosts_get_network() -> None:
    assert assessment_types(scope_dict(url_prefixes=[URL]), []) == ["web", "api"]
    assert assessment_types(scope_dict(ip_ranges=["10.0.0.0/24"]), []) == ["network"]
    assert assessment_types(scope_dict(domains=["lab.example"]), []) == ["network"]
    assert assessment_types(scope_dict(repo_paths=["/workspace/code/s"]), []) == []


def test_the_type_named_in_the_chat_wins_and_the_newest_counts() -> None:
    scope = scope_dict(url_prefixes=[URL])
    chat = ["Assessment type: Web URL", "scan it", "assessment type: api"]

    assert assessment_types(scope, chat) == ["api"]
    assert assessment_types(scope, ["Assessment type: Web URL"]) == ["web"]
    assert assessment_types(scope, ["Assessment type: Source Code"]) == []


def test_a_code_scope_gets_no_methodology() -> None:
    assert techniques_text(scope_dict(repo_paths=["/workspace/code/s"]), []) == ""


def test_only_the_scope_tools_are_plannable_and_manual_ones_are_for_a_person() -> None:
    scope = scope_dict(url_prefixes=[URL], allowed_tools=["WHATWEB", "NUCLEI"])

    text = techniques_text(scope, ["Assessment type: Web URL"])

    assert "### Web application" in text and "### API" not in text
    assert "- fingerprint: " in text and "WHATWEB {url}" in text
    assert "HTTPX_PROBE" not in text  # not in the scope's tools
    assert "Not possible with this scope (never plan these): Directory discovery" in text
    assert "A person checks these (never plan a tool step): Authorization testing" in text


def test_testssl_needs_an_https_prefix() -> None:
    plain = scope_dict(url_prefixes=["http://juice-shop:3000/"], allowed_tools=["TESTSSL"])
    secure = scope_dict(url_prefixes=[URL], allowed_tools=["TESTSSL"])

    assert "TESTSSL {url}" not in techniques_text(plain, ["Assessment type: Web URL"])
    assert "TESTSSL {url}" in techniques_text(secure, ["Assessment type: Web URL"])


def test_with_allowed_ports_host_discovery_and_os_detection_are_not_planned() -> None:
    scope = scope_dict(ip_ranges=["10.0.0.0/24"], allowed_tools=["NMAP"], allowed_ports=[22, 80])

    text = techniques_text(scope, [])

    assert "NMAP {host} -Pn -sV -p {ports}" in text
    assert "NMAP {host} -sn" not in text and "NMAP {host} -O" not in text
    assert "Host discovery (needs nmap" in text and "OS fingerprinting (needs nmap" in text


def test_without_allowed_ports_host_discovery_is_planned() -> None:
    scope = scope_dict(ip_ranges=["10.0.0.0/24"], allowed_tools=["NMAP"])

    assert "NMAP {host} -sn" in techniques_text(scope, [])


def test_the_time_window_does_not_hide_the_methodology() -> None:
    scope = scope_dict(
        url_prefixes=[URL],
        allowed_tools=["WHATWEB"],
        window_start="2020-01-01T00:00:00+00:00",
        window_end="2020-01-02T00:00:00+00:00",
    )

    assert "WHATWEB {url}" in techniques_text(scope, [])


# --- the prompts ------------------------------------------------------------------------


def state(**changes: Any) -> dict[str, Any]:
    scope = scope_dict(url_prefixes=[URL], allowed_tools=["NUCLEI"])
    return {"scope": scope, "goal": "g", "messages": [], "tool_results": ["x"]} | changes


def test_the_plan_and_reflect_prompts_carry_the_techniques() -> None:
    plan = plan_messages(state())[-1].content
    reflect = reflect_messages(state())[-1].content

    assert "## Techniques to cover" in plan and "NUCLEI {url} -tags tech,cve" in plan
    assert "## Techniques to cover" in reflect


def test_findings_reach_the_plan_and_reflect_prompts() -> None:
    # The planner follows leads in the evidence, so recorded findings must be visible to
    # it (a version, a parameter, a path), not only the newest raw outputs.
    finding = {
        "code": "RCX-1",
        "title": "Apache httpd 2.2.8",
        "target": URL,
        "severity_status": "NONE",
    }
    with_findings = state(findings=[finding])

    assert "RCX-1" in plan_messages(with_findings)[-1].content
    assert "Apache httpd 2.2.8" in reflect_messages(with_findings)[-1].content
    # The rendered findings block is fenced as <findings>; with none it is absent, so an
    # empty run adds no noise. (The prompt text itself mentions "## Findings", so assert
    # on the fence tag, which only appears when findings are actually rendered.)
    assert "<findings>" not in plan_messages(state())[-1].content


def test_prior_reasoning_reaches_the_plan_and_reflect_prompts() -> None:
    # The agent carries its own earlier per-step reasoning forward, so each step builds on
    # what it decided before instead of re-deriving it from the findings every time.
    with_reasoning = state(prior_reasoning=["Step 1: whatweb says WordPress, pursuing wpscan."])

    for content in (
        plan_messages(with_reasoning)[-1].content,
        reflect_messages(with_reasoning)[-1].content,
    ):
        # the <earlier_reasoning> fence only renders when prior reasoning is actually present
        # (the header phrase itself also appears in the prompt instructions, so assert the fence)
        assert "<earlier_reasoning>" in content
        assert "pursuing wpscan" in content
    assert "<earlier_reasoning>" not in plan_messages(state())[-1].content


def test_a_code_plan_prompt_has_no_empty_section() -> None:
    code = state(scope=scope_dict(repo_paths=["/w"], allowed_tools=["SEMGREP"]))

    text = plan_messages(code)[-1].content

    assert "## Techniques to cover" not in text and "\n\n\n\n" not in text


def test_schemathesis_targets_a_non_default_doc_path() -> None:
    # A Spring/Swagger API serves its OpenAPI doc at /v3/api-docs, not /openapi.json. With that
    # doc URL in scope, schemathesis uses it directly; the base URL stays for crawling.
    scope = Scope(
        allowed_tools=["schemathesis"],
        ip_ranges=[],
        url_prefixes=["http://api.example.com/", "http://api.example.com/v3/api-docs"],
    )
    values = sample_values(scope)
    assert values["schema"] == "http://api.example.com/v3/api-docs"
    assert values["url"] == "http://api.example.com/"  # the base, not the doc


def test_schemathesis_falls_back_to_openapi_json_when_no_doc_url_is_in_scope() -> None:
    scope = Scope(
        allowed_tools=["schemathesis"], ip_ranges=[], url_prefixes=["http://api.example.com/"]
    )
    assert sample_values(scope)["schema"] == "http://api.example.com/openapi.json"


def test_the_default_goal_is_to_find_vulnerabilities() -> None:
    assert "vulnerabilities" in DEFAULT_GOAL and "discovery first" in DEFAULT_GOAL


# --- the vuln-finding improvements (benchmark 2026-11-06) ------------------------------


def _nuclei_steps(kind: str) -> set[str]:
    return {
        step
        for technique in methodology()[kind]
        for step in technique.steps
        if split_step(step)[0] == "NUCLEI"
    }


def test_nuclei_is_one_consolidated_run_per_web_and_api_type() -> None:
    """Every technique that uses nuclei shares the SAME command, so the agent runs
    nuclei once per URL instead of looping and being blocked for a repeated command."""
    assert len(_nuclei_steps("web")) == 1
    assert len(_nuclei_steps("api")) == 1


def test_the_network_scan_detects_versions_and_never_scans_ports_plain_first() -> None:
    steps = {step for t in methodology()["network"] for step in t.steps}
    nmap_port_steps = {s for s in steps if "{ports}" in s and split_step(s)[0] == "NMAP"}
    # Every ported nmap step detects versions (-sV); there is no plain port scan to run
    # first and leave version-less findings that later dedupe over the -sV results.
    assert nmap_port_steps == {"NMAP {host} -Pn -sV -p {ports}"}


def test_plan_and_reflect_tell_the_agent_to_converge_and_stop() -> None:
    from reconix_ai.agent.prompts import PROMPTS_DIR, read_markdown

    plan = read_markdown(PROMPTS_DIR / "plan.md").lower()
    reflect = read_markdown(PROMPTS_DIR / "reflect.md").lower()
    assert "already run" in plan and "stop" in plan
    assert "already run" in reflect


# --- the technique expansions (more tools, 2026-11-06) --------------------------------


def test_sqlmap_is_a_gated_confirm_step_in_input_validation() -> None:
    """sqlmap confirms a flagged SQLi; it is destructive, so it only ever runs as a
    HIGH, operator-approved step, and only from input validation."""
    assert is_destructive("sqlmap")
    for kind in ("web", "api"):
        iv = next(t for t in methodology()[kind] if t.key == "input_validation")
        assert "sqlmap" in iv.tools
        assert any(split_step(step)[0] == "SQLMAP" for step in iv.steps)
    # sqlmap never appears in a technique other than input validation.
    for techniques in methodology().values():
        for technique in techniques:
            if technique.key != "input_validation":
                assert all(split_step(step)[0] != "SQLMAP" for step in technique.steps)


def test_network_misconfiguration_chains_smb_and_snmp() -> None:
    mis = next(t for t in methodology()["network"] if t.key == "misconfiguration")

    assert {"enum4linux", "onesixtyone"} <= set(mis.tools)
    assert {"ENUM4LINUX", "ONESIXTYONE"} <= {split_step(step)[0] for step in mis.steps}


def test_schemathesis_runs_the_full_check_set_for_api() -> None:
    schema_steps = {
        step
        for technique in methodology()["api"]
        for step in technique.steps
        if split_step(step)[0] == "SCHEMATHESIS"
    }

    assert schema_steps == {"SCHEMATHESIS {schema} --checks all"}


def test_sqlmap_shows_only_when_it_is_an_allowed_tool() -> None:
    with_sqlmap = scope_dict(
        url_prefixes=[URL], allowed_tools=["NUCLEI", "DALFOX", "SQLMAP"], max_risk="HIGH"
    )
    without = scope_dict(url_prefixes=[URL], allowed_tools=["NUCLEI", "DALFOX"], max_risk="HIGH")

    assert "SQLMAP {url}" in techniques_text(with_sqlmap, ["Assessment type: Web URL"])
    assert "SQLMAP {url}" not in techniques_text(without, ["Assessment type: Web URL"])
