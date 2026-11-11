"""Web URL template: a web application reached over HTTP(S)."""

from ...models import ScopeManifest, Template
from ...models.parser import ParsedTarget
from .base import RunBundle, RunProfile, run_bundle

SCOPE_PROMPT = (
    "You scope an authorized assessment of a web application reached over HTTP(S). It "
    "covers these techniques: technology fingerprinting and version detection (whatweb, "
    "httpx_probe, nuclei), directory discovery (katana crawls; ffuf brute-forces paths with "
    "Core's wordlist), security headers and configuration (nuclei, nikto scans the server "
    "for known issues), TLS (testssl), authentication and input validation (nuclei, dalfox "
    "for XSS). The default tools are whatweb, katana, Nuclei, testssl, ffuf, nikto and "
    "dalfox (dalfox tests a URL parameter found by crawling for XSS; ffuf and nikto are "
    "non-destructive). wpscan is for WordPress. Authorization (IDOR) and file upload are "
    "checked by hand. Never suggest destructive, exploitation or password tools (sqlmap, "
    "commix, hydra, msfconsole, ZAP's active scan). Respect excluded paths like /admin."
)
SUGGEST_CATEGORIES = ["web", "zap"]
SPEC = Template("web_url", "Web URL", "Web application at a URL",
                target_hint="the site's URL", example="https://shop.example.com")

TOOLS = ["whatweb", "Katana", "Nuclei", "testssl.sh", "ffuf", "nikto", "dalfox"]
# the scope tools each phase uses (the plan shows those still in the approved scope)
PHASE_TOOLS = {
    "discovery": ("whatweb", "Katana", "ffuf"),
    "scanning": ("Nuclei", "testssl.sh", "nikto"),
    "validation": ("Nuclei", "dalfox"),
}


def build_scope(parsed: ParsedTarget) -> ScopeManifest:
    return ScopeManifest(
        kind="web_url",
        target_url=parsed.target_url,
        assessment_type="Web URL",
        allowed_actions=["Discovery", "vulnerability scanning", "limited validation"],
        allowed_methods=["GET", "POST"],
        excluded_paths=["/admin"],
        time_limit_minutes=0,  # no time limit by default; set one in the scope edit form
        tools=list(TOOLS),
    )


def build_run(assessment) -> RunBundle:
    scope = build_scope(
        ParsedTarget(
            "web_url", assessment.target, assessment.target_url, "web application", "web_url", True
        )
    )
    profile = RunProfile(
        target_kind="web application",
        tools=scope.tools,
        plan=(
            ("discovery", "Map the site"),
            ("scanning", "Scan for weaknesses"),
            ("validation", "Validate findings"),
            ("analysis", "Correlate & dedupe findings"),
            ("report", "Generate report"),
        ),
        methodology=("Guided by OWASP WSTG", "OWASP Top 10 (2025)"),
    )
    return run_bundle(scope, profile, PHASE_TOOLS)
