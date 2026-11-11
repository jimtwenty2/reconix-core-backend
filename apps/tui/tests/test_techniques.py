"""Each template's testing techniques, its default tools, and the report's test coverage."""

import dataclasses

import pytest

from reconix import store
from reconix.core_api import sync
from reconix.core_api.scope_map import api_tool
from reconix.models.parser import ParsedTarget
from reconix.store import lists
from reconix.store.kali_catalog import KALI_TOOLS, tool_purpose
from reconix.store.report_docx import write_docx
from reconix.store.report_html import render_html
from reconix.store.templates import MODULES
from reconix.store.templates.techniques import (
    MANUAL,
    NOT_POSSIBLE_TEXT,
    coverage,
    grouped,
    status_text,
    techniques_for,
)
from reconix.widgets.manifest import manifest_text

from .support import run_to


def _scope(template_id: str, with_spec: bool = False):
    module = MODULES[template_id]
    parsed = ParsedTarget(
        template_id, "x.example.com", "https://x.example.com", "t", template_id, True
    )
    if template_id == "api":
        return module.build_scope(parsed, with_spec=with_spec)
    return module.build_scope(parsed)


# --- the catalog -------------------------------------------------------------------------------
def test_each_template_lists_the_techniques_from_the_map():
    assert len(techniques_for("web_url")) == 10
    assert len(techniques_for("network")) == 10
    assert len(techniques_for("api")) == 12
    assert [t.key for t in techniques_for("source")] == [
        "static_analysis",
        "secrets",
        "dependencies",
    ]
    assert techniques_for("nope") == []


def test_every_technique_tool_is_a_safe_kali_catalog_tool():
    for template_id in MODULES:
        for tech in techniques_for(template_id):
            assert tech.tools or tech.mode == MANUAL, tech.key
            for tool in tech.tools:
                assert tool in KALI_TOOLS, tool
                assert not KALI_TOOLS[tool].destructive, tool


@pytest.mark.parametrize("template_id", ["web_url", "api", "network", "source"])
def test_every_default_scope_tool_is_in_the_kali_catalog(template_id):
    for with_spec in (False, True):
        scope = _scope(template_id, with_spec)
        for tool in scope.tools:
            name = api_tool(tool).lower()
            assert name in KALI_TOOLS, tool
            assert not KALI_TOOLS[name].destructive, tool
            assert tool_purpose(name), tool


def test_the_new_defaults():
    assert _scope("web_url").tools == [
        "whatweb",
        "Katana",
        "Nuclei",
        "testssl.sh",
        "ffuf",
        "nikto",
        "dalfox",
    ]
    # ffuf drives API endpoint and version discovery (Core supplies the wordlist).
    assert _scope("api").tools == ["httpx", "Katana", "ffuf", "Nuclei", "schemathesis", "dalfox"]
    # schemathesis is a default now, so an operator spec does not change the tool list.
    assert _scope("api", with_spec=True).tools == [
        "httpx",
        "Katana",
        "ffuf",
        "Nuclei",
        "schemathesis",
        "dalfox",
    ]
    assert _scope("network").tools == [
        "nmap",
        "Nuclei",
        "testssl.sh",
        "enum4linux",
        "onesixtyone",
    ]
    assert {3306, 3389, 445, 5432, 6379, 3000, 161} <= set(_scope("network").allowed_ports)
    assert _scope("source").tools == ["Semgrep", "gitleaks", "trivy", "grype", "osv-scanner",
                                      "syft"]


def test_new_technique_tools_are_defaults_and_non_destructive():
    # Wider technique coverage: nikto+ffuf on web, enum4linux+onesixtyone on network,
    # schemathesis on api. All must be real, non-destructive Kali catalog tools.
    from reconix.store.kali_catalog import KALI_TOOLS

    expected = {
        "web_url": ["ffuf", "nikto"],
        "network": ["enum4linux", "onesixtyone"],
        "api": ["schemathesis"],
    }
    for template_id, tools in expected.items():
        scope_tools = _scope(template_id).tools
        for tool in tools:
            assert tool in scope_tools, (template_id, tool)
            name = api_tool(tool).lower()
            assert name in KALI_TOOLS and not KALI_TOOLS[name].destructive, tool


def test_sqlmap_is_never_a_default_tool():
    # sqlmap is HIGH-risk/destructive: available only when the operator ticks it, never
    # a default on any template.
    from reconix.store.kali_catalog import KALI_TOOLS

    assert KALI_TOOLS["sqlmap"].destructive
    for template_id in ("web_url", "api", "network", "source"):
        assert "sqlmap" not in [api_tool(t).lower() for t in _scope(template_id).tools]


def test_dalfox_is_a_default_web_and_api_tool_for_the_xss_chain():
    # dalfox lets the agent follow a katana-found parameter into an XSS test; it must be a
    # real, non-destructive Kali catalog tool.
    from reconix.store.kali_catalog import KALI_TOOLS
    from reconix.store.tools import known_tool

    for template_id in ("web_url", "api"):
        assert "dalfox" in _scope(template_id).tools
    assert known_tool("dalfox") == "dalfox"
    assert "dalfox" in KALI_TOOLS and not KALI_TOOLS["dalfox"].destructive


# --- coverage ---------------------------------------------------------------------------------
def test_coverage_marks_tested_partial_not_run_and_manual():
    rows = {r["key"]: r for r in coverage("web_url", ["NUCLEI", "whatweb"])}
    assert rows["fingerprint"]["status"] == "TESTED"
    assert rows["fingerprint"]["tools"] == ["whatweb"]
    assert rows["authentication"]["status"] == "PARTIAL"  # nuclei ran, rest by hand
    assert rows["directories"]["status"] == "NOT_RUN"
    assert rows["authorization"]["status"] == "MANUAL"
    assert rows["tls"]["status"] == "NOT_RUN"


def test_coverage_reads_any_tool_spelling():
    rows = {r["key"]: r for r in coverage("web_url", ["testssl.sh"])}
    assert rows["tls"]["status"] == "TESTED"
    assert rows["tls"]["tools"] == ["testssl"]


def test_not_run_says_when_the_scope_could_not_do_it():
    rows = {r["key"]: r for r in coverage("network", [], ["nmap"])}
    assert status_text(rows["tls"]) == NOT_POSSIBLE_TEXT  # testssl not in the scope
    assert status_text(rows["services"]) == "Not run"  # nmap was in the scope
    assert status_text(rows["segmentation"]) == "Check by hand"


def test_grouped_names_per_mode():
    groups = grouped("api")
    assert "CORS testing" in groups["auto"]
    assert "Input validation" in groups["partial"]
    assert "Mass assignment" in groups["manual"]


# --- the scope card ---------------------------------------------------------------------------
def test_the_scope_card_shows_what_the_scope_can_and_cannot_test():
    # The Techniques section is scope-aware: the default web scope has every tool, so every
    # auto/partial technique is coverable and nothing is a gap.
    text = manifest_text(_scope("web_url"), with_suggestions=False).plain
    assert "Techniques" in text
    assert "can test: Technology fingerprinting" in text
    assert "partly; finish by hand: Authentication testing, Input validation" in text
    assert "you check by hand: Authorization testing, File upload testing" in text


def test_the_scope_preview_flags_a_gap_and_names_the_tool_to_add():
    # A scope missing a technique's tool shows it as a gap, naming the tool to add, so the
    # operator can close it by editing the scope (the preview is informational; the harness
    # still enforces scope at run time).
    preview = store.scope_coverage_preview("web_url", ["whatweb"])  # only whatweb chosen
    assert "Technology fingerprinting" in [item["name"] for item in preview["can"]]
    gaps = {item["name"]: item["needs"] for item in preview["gap"]}
    assert "TLS assessment" in gaps and "testssl" in gaps["TLS assessment"]
    assert "Authorization testing" in [item["name"] for item in preview["manual"]]


def test_the_scope_card_flags_a_gap_with_the_tool_to_add():
    # A scope missing a tool shows the "can't test" line on the card, naming the tool to add.
    scope = dataclasses.replace(_scope("web_url"), tools=["whatweb"])
    text = manifest_text(scope, with_suggestions=False).plain
    assert "can't test: " in text
    assert "TLS assessment (add testssl)" in text


# --- the first chat line ----------------------------------------------------------------------
def test_the_first_message_names_the_assessment_type():
    store.start_run("Assess https://staging.example.com for web security issues.")
    assessment = lists.current()
    first = sync.first_message(assessment)
    assert first.splitlines()[0] == "Assessment type: Web URL"
    assert first.splitlines()[1] == assessment.requests[0].text


# --- the report -------------------------------------------------------------------------------
def test_the_report_carries_the_coverage_of_what_ran(tmp_path):
    run_to(None)
    data = store.report_data()
    rows = {r["key"]: r for r in data["coverage"]}
    assert rows["versions"]["status"] == "TESTED"  # nuclei ran on the fake API
    assert rows["authorization"]["status"] == "MANUAL"
    html = render_html(data)
    assert "Test coverage" in html and "Check by hand" in html
    assert "Authorization testing: IDOR, privilege escalation" in html  # the checklist
    path = tmp_path / "r.docx"
    write_docx(data, path)
    assert path.stat().st_size > 0
