"""Web URL template: a web application reached over HTTP(S)."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized assessment of a web application reached over HTTP(S). The "
    "default tools are Nuclei and OWASP ZAP for vulnerability scanning. For content and "
    "path discovery suggest katana (crawl the site) or ffuf/gobuster (brute-force paths, "
    "which need a wordlist). whatweb and httpx fingerprint the stack; wpscan is for "
    "WordPress; nikto is a quick server check. Never suggest destructive, exploitation or "
    "password tools (sqlmap, hydra, msfconsole). Respect excluded paths like /admin."
)
SUGGEST_CATEGORIES = ["web", "zap"]
SPEC = Template("web_url", "Web URL", "Web application at a URL",
                target_hint="the site's URL", example="https://shop.example.com")

TOOLS = ["Nuclei", "OWASP ZAP"]
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {"discovery": ("OWASP ZAP",), "scanning": ("Nuclei", "OWASP ZAP"),
               "validation": ("OWASP ZAP",)}


def build_scope(parsed: ParsedTarget) -> ScopeManifest:
    return ScopeManifest(
        kind="web_url", target_url=parsed.target_url, assessment_type="Web URL",
        allowed_actions=["Discovery", "vulnerability scanning", "limited validation"],
        allowed_methods=["GET", "POST"],
        excluded_paths=["/admin"],
        time_limit_minutes=0,   # no time limit by default; set one in the scope edit form
        tools=list(TOOLS),
    )


def build_run(assessment) -> RunBundle:
    scope = build_scope(ParsedTarget("web_url", assessment.target, assessment.target_url,
                                     "web application", "web_url", True))
    profile = RunProfile(target_kind="web application", tools=scope.tools, plan=(
                               ("discovery", "Map the site"),
                               ("scanning", "Scan for weaknesses"),
                               ("validation", "Validate findings"),
                               ("analysis", "Correlate & dedupe findings"),
                               ("report", "Generate report")),
                         methodology=("OWASP WSTG", "OWASP Top 10 (2021)"))
    return run_bundle(scope, profile, PHASE_TOOLS)
