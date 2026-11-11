"""API template: a REST/GraphQL service."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized assessment of a REST or GraphQL API. It covers these "
    "techniques: endpoint and API version discovery (katana, ffuf, arjun for hidden "
    "parameters), authentication, CORS, data exposure and SSRF checks (nuclei), HTTP "
    "methods (nuclei, httpx_probe), and input and schema validation (schemathesis drives "
    "the API from its OpenAPI document at <base>/openapi.json; dalfox tests a parameter "
    "found by crawling for XSS). The default tools are httpx, katana, ffuf, Nuclei, "
    "schemathesis and dalfox; newman only replays a Postman collection. "
    "Authorization (BOLA/IDOR), rate limits and mass assignment are checked by hand. Never "
    "suggest destructive, exploitation or password tools (sqlmap, hydra). Respect excluded "
    "paths like /internal and /admin."
)
SUGGEST_CATEGORIES = ["web", "api", "zap"]
SPEC = Template("api", "API", "REST and GraphQL endpoints",
                target_hint="the API's base URL", example="https://api.example.com/v1")

# schemathesis is a default: the agent drives it from the OpenAPI document at
# <base>/openapi.json, which is inside the approved URL prefix, so no operator-supplied
# spec is needed. An explicit operator spec still enriches the plan text (see build_run).
TOOLS = ["httpx", "Katana", "ffuf", "Nuclei", "schemathesis", "dalfox"]
SPEC_TOOLS = []  # kept for build_scope's signature; schemathesis is now a default
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {
    "discovery": ("httpx", "Katana", "ffuf"),
    "scanning": ("Nuclei", "schemathesis"),
    "validation": ("Nuclei", "schemathesis", "dalfox"),
}


def build_scope(parsed: ParsedTarget, with_spec: bool = False) -> ScopeManifest:
    return ScopeManifest(
        kind="api",
        target_url=parsed.target_url,
        assessment_type="API",
        allowed_actions=["Endpoint discovery", "auth checks", "limited validation"],
        allowed_methods=["GET", "POST"],
        excluded_paths=["/internal", "/admin"],
        time_limit_minutes=0,  # no time limit by default; set one in the scope edit form
        tools=list(TOOLS) + (list(SPEC_TOOLS) if with_spec else []),
    )


def _plain(text: str) -> str:
    """Spec text for plan and report lines: no square brackets (those are markup)."""
    return text.replace("[", "(").replace("]", ")")


def build_run(assessment) -> RunBundle:
    url, host = assessment.target_url, assessment.target
    spec = getattr(assessment, "api_spec", None)
    scope = build_scope(
        ParsedTarget("api", host, url, "API service", "api", True), with_spec=spec is not None
    )
    profile = RunProfile(
        target_kind="API service",
        tools=scope.tools,
        plan=(
            ("discovery", "Map API surface"),
            (
                "scanning",
                f"Test {spec.total} endpoints from {_plain(spec.label)}"
                if spec
                else "Scan endpoints",
            ),
            ("validation", "Validate authz & inputs"),
            ("analysis", "Correlate & dedupe findings"),
            ("report", "Generate report"),
        ),
        methodology=("Guided by OWASP API Security Top 10 (2023)", "OWASP WSTG")
        + (
            (
                f"Operator-supplied OpenAPI spec: {_plain(spec.label)} "
                f"(OpenAPI {spec.spec_version}, {spec.total} endpoints)",
            )
            if spec
            else ()
        ),
    )
    return run_bundle(scope, profile, PHASE_TOOLS)
