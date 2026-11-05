"""API template: a REST/GraphQL service."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized assessment of a REST or GraphQL API. The default tools are "
    "Nuclei and OWASP ZAP (API scan). For endpoint discovery suggest katana or ffuf; "
    "schemathesis and newman (Postman) test documented endpoints. httpx fingerprints the "
    "service. Never suggest destructive, exploitation or password tools. Respect excluded "
    "paths like /internal and /admin."
)
SUGGEST_CATEGORIES = ["web", "api", "zap"]
SPEC = Template("api", "API", "REST and GraphQL endpoints",
                target_hint="the API's base URL", example="https://api.example.com/v1")

TOOLS = ["Nuclei", "Postman", "ZAP API scan"]
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {"discovery": ("Postman",), "scanning": ("ZAP API scan", "Nuclei"),
               "validation": ("Postman",)}


def build_scope(parsed: ParsedTarget) -> ScopeManifest:
    return ScopeManifest(
        kind="api", target_url=parsed.target_url, assessment_type="API",
        allowed_actions=["Endpoint discovery", "auth checks", "limited validation"],
        allowed_methods=["GET", "POST"],
        excluded_paths=["/internal", "/admin"],
        time_limit_minutes=0,   # no time limit by default; set one in the scope edit form
        tools=list(TOOLS),
    )


def _plain(text: str) -> str:
    """Spec text for plan and report lines: no square brackets (those are markup)."""
    return text.replace("[", "(").replace("]", ")")


def build_run(assessment) -> RunBundle:
    url, host = assessment.target_url, assessment.target
    spec = getattr(assessment, "api_spec", None)
    scope = build_scope(ParsedTarget("api", host, url, "API service", "api", True))
    profile = RunProfile(
        target_kind="API service", tools=scope.tools,
        plan=(("discovery", "Map API surface"),
              ("scanning", f"Test {spec.total} endpoints from {_plain(spec.label)}"
                           if spec else "Scan endpoints"),
              ("validation", "Validate authz & inputs"),
              ("analysis", "Correlate & dedupe findings"),
              ("report", "Generate report")),
        methodology=("OWASP API Security Top 10 (2023)", "OWASP WSTG")
        + ((f"Operator-supplied OpenAPI spec: {_plain(spec.label)} "
            f"(OpenAPI {spec.spec_version}, {spec.total} endpoints)",) if spec else ()),
    )
    return run_bundle(scope, profile, PHASE_TOOLS)
