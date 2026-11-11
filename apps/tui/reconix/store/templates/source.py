"""Source Code template: a static review of a repository."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized static review of a source repository. Use every code tool: "
    "Semgrep (static analysis), gitleaks (secrets), and trivy, grype and osv-scanner "
    "(dependencies), plus syft (SBOM). All read the code only; never suggest tools that "
    "reach the network or run the code. Respect excluded folders like node_modules and .git."
)
SUGGEST_CATEGORIES = ["source"]
SPEC = Template("source", "Source Code", "Static review of a repository",
                target_hint="a GitHub repo URL or a local path",
                example="https://github.com/acme/app")

# All the code scanners the backend runs out of the box (schemas/code.py CODE_TOOLS), so a
# scan uses every one, not just three. SONAR_SCAN is left out of the default: it needs a
# SonarQube server, so add it to a scope by hand when one is configured.
TOOLS = ["Semgrep", "gitleaks", "trivy", "grype", "osv-scanner", "syft"]
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {"scanning": ("Semgrep", "gitleaks", "trivy", "grype", "osv-scanner", "syft"),
               "validation": ("Semgrep",)}


def build_scope(parsed: ParsedTarget) -> ScopeManifest:
    return ScopeManifest(
        kind="source", target_url=parsed.target_url, assessment_type="Source Code",
        allowed_actions=["Dependency scan", "secret scan", "static analysis"],
        allowed_methods=["read"],
        excluded_paths=[".git", "node_modules", "vendor", "secrets"],
        time_limit_minutes=0,   # no time limit by default; set one in the scope edit form
        tools=list(TOOLS),
    )


def build_run(assessment) -> RunBundle:
    scope = build_scope(ParsedTarget("source", assessment.target, assessment.target_url,
                                     "source repository", "source", True))
    profile = RunProfile(target_kind="source repository", tools=scope.tools, plan=(
                               ("discovery", "Inventory the code"),
                               ("scanning", "Static, secret & dependency scans"),
                               ("validation", "Review findings"),
                               ("analysis", "Correlate & dedupe findings"),
                               ("report", "Generate report")),
                         methodology=("Guided by OWASP ASVS", "CWE Top 25"))
    return run_bundle(scope, profile, PHASE_TOOLS)
