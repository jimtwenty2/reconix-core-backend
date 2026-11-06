"""The testing techniques each template covers, and how much of each a run tested.

Every template lists what a tester investigates for its kind of target (web, API,
network, source code). A technique is:

- `auto`: a non-destructive Kali catalog tool covers it; the AI plans it.
- `partial`: a tool covers part of it; the rest is a check done by hand.
- `manual`: no safe automated tool; it is on the tester's checklist.

The same map is in the AI's planning prompt (services/ai), so the plan aims at these
techniques. Destructive tools (sqlmap, commix, hydra, ZAP's active scan) are never listed
here: they run only when the operator ticks them in the scope.
"""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from ...core_api.scope_map import api_tool

AUTO, PARTIAL, MANUAL = "auto", "partial", "manual"

# Coverage of one technique after a run.
TESTED = "TESTED"      # a tool of the technique finished on this assessment
PARTIAL_DONE = "PARTIAL"  # a partial technique's tool finished: finish it by hand
NOT_RUN = "NOT_RUN"    # an auto or partial technique none of whose tools finished
MANUAL_CHECK = "MANUAL"   # a manual technique: the tester checks it by hand

STATUS_TEXT = {
    TESTED: "Tested",
    PARTIAL_DONE: "Partly tested · finish by hand",
    NOT_RUN: "Not run",
    MANUAL_CHECK: "Check by hand",
}
NOT_POSSIBLE_TEXT = "Not run (not possible with this scope)"


def status_text(row: Dict[str, object]) -> str:
    """A coverage row's status in words: NOT_RUN says when the scope had none of its tools."""
    if row.get("status") == NOT_RUN and not row.get("possible", True):
        return NOT_POSSIBLE_TEXT
    return STATUS_TEXT.get(str(row.get("status")), str(row.get("status")))


@dataclass(frozen=True)
class Technique:
    key: str
    name: str
    investigates: str
    tools: Tuple[str, ...]   # Kali catalog names (lowercase)
    mode: str                # auto, partial or manual


def _t(key: str, name: str, investigates: str, tools: str, mode: str) -> Technique:
    return Technique(key, name, investigates, tuple(tools.split()), mode)


WEB: Tuple[Technique, ...] = (
    _t("fingerprint", "Technology fingerprinting", "Web server, framework, CMS, libraries",
       "whatweb httpx_probe", AUTO),
    _t("versions", "Version detection", "Outdated Apache, Nginx, PHP, etc.",
       "nuclei whatweb nikto", AUTO),
    _t("directories", "Directory discovery", "Hidden directories and files",
       "katana ffuf gobuster", AUTO),
    _t("authentication", "Authentication testing", "Weak login, broken authentication",
       "nuclei", PARTIAL),
    _t("authorization", "Authorization testing", "IDOR, privilege escalation", "", MANUAL),
    _t("input_validation", "Input validation", "SQL injection, XSS, command injection",
       "dalfox nuclei", PARTIAL),
    _t("headers", "Security headers", "CSP, HSTS, X-Frame-Options", "nuclei nikto", AUTO),
    _t("tls", "TLS assessment", "Weak protocols and certificates", "testssl", AUTO),
    _t("file_upload", "File upload testing", "Unrestricted file uploads", "", MANUAL),
    _t("configuration", "Configuration testing", "Debug mode, exposed secrets, default pages",
       "nuclei nikto", AUTO),
)

NETWORK: Tuple[Technique, ...] = (
    _t("host_discovery", "Host discovery", "Identify live devices", "nmap", AUTO),
    _t("port_scan", "Port scanning", "Find open TCP/UDP ports", "nmap", AUTO),
    _t("services", "Service detection", "Identify running services", "nmap", AUTO),
    _t("versions", "Version detection", "Detect outdated service versions", "nmap", AUTO),
    _t("os_fingerprint", "OS fingerprinting", "Identify operating systems", "nmap", PARTIAL),
    _t("cve_matching", "CVE matching", "Compare detected versions against known CVEs",
       "nuclei", AUTO),
    _t("misconfiguration", "Misconfiguration checks", "Default credentials, insecure services",
       "nuclei enum4linux onesixtyone", PARTIAL),
    _t("tls", "SSL/TLS testing", "Weak ciphers and protocols", "testssl", AUTO),
    _t("firewall", "Firewall assessment", "Unexpectedly exposed services", "nmap", PARTIAL),
    _t("segmentation", "Network segmentation", "Unauthorized access between network zones",
       "", MANUAL),
)

API: Tuple[Technique, ...] = (
    _t("endpoints", "Endpoint discovery", "Find undocumented API endpoints",
       "katana ffuf arjun", AUTO),
    _t("authentication", "Authentication testing", "JWT, API keys, OAuth", "nuclei", PARTIAL),
    _t("authorization", "Authorization testing", "BOLA / IDOR", "", MANUAL),
    _t("rate_limit", "Rate-limit testing", "Brute-force and request abuse protections", "",
       MANUAL),
    _t("input_validation", "Input validation", "SQL injection, NoSQL injection",
       "schemathesis nuclei", PARTIAL),
    _t("mass_assignment", "Mass assignment", "Unauthorized modification of fields", "",
       MANUAL),
    _t("data_exposure", "Data exposure", "Sensitive information in API responses",
       "nuclei schemathesis", PARTIAL),
    _t("http_methods", "HTTP method testing", "Unexpected methods enabled",
       "nuclei httpx_probe", PARTIAL),
    _t("cors", "CORS testing", "Unsafe cross-origin access", "nuclei", AUTO),
    _t("schema_validation", "Schema validation", "Incorrect request/response validation",
       "schemathesis", AUTO),
    _t("ssrf", "SSRF testing", "Unsafe server-side URL fetching", "nuclei", PARTIAL),
    _t("api_versions", "API version testing", "Old or deprecated endpoints", "ffuf katana",
       AUTO),
)

SOURCE: Tuple[Technique, ...] = (
    _t("static_analysis", "Static analysis", "Injection, unsafe code patterns", "semgrep",
       AUTO),
    _t("secrets", "Secret scanning", "Keys, tokens and passwords in the code", "gitleaks",
       AUTO),
    _t("dependencies", "Dependency scanning", "Known-vulnerable packages",
       "trivy grype osv_scanner", AUTO),
)

TECHNIQUES: Dict[str, Tuple[Technique, ...]] = {
    "web_url": WEB, "api": API, "network": NETWORK, "source": SOURCE,
}


def techniques_for(template_id: str) -> List[Technique]:
    """The template's techniques, in order (none for an unknown template)."""
    return list(TECHNIQUES.get(template_id, ()))


def tool_key(name: str) -> str:
    """A tool name as the catalog spells it ("testssl.sh" -> "testssl", "NMAP" -> "nmap")."""
    return api_tool(name).lower()


def coverage(template_id: str, finished_tools: Iterable[str],
             scope_tools: Optional[Iterable[str]] = None) -> List[Dict[str, object]]:
    """One row per technique: its name, what it investigates, status and the tools that ran.

    `finished_tools` are the tools whose runs completed on this assessment, in any spelling
    (scope names, catalog names or the API's UPPERCASE names). `scope_tools` are the
    approved scope's tools: a technique none of whose tools is among them is marked not
    `possible` (its NOT_RUN reads "not possible with this scope"). None: not checked.
    """
    finished = {tool_key(name) for name in finished_tools if name}
    in_scope = (None if scope_tools is None
                else {tool_key(name) for name in scope_tools if name})
    rows: List[Dict[str, object]] = []
    for tech in techniques_for(template_id):
        ran = [tool for tool in tech.tools if tool in finished]
        if tech.mode == MANUAL:
            status = MANUAL_CHECK
        elif not ran:
            status = NOT_RUN
        else:
            status = TESTED if tech.mode == AUTO else PARTIAL_DONE
        possible = in_scope is None or any(tool in in_scope for tool in tech.tools)
        rows.append({"key": tech.key, "name": tech.name, "investigates": tech.investigates,
                     "mode": tech.mode, "status": status, "tools": ran,
                     "possible": possible})
    return rows


def grouped(template_id: str) -> Dict[str, List[str]]:
    """Technique names per mode, for the scope card ({"auto": [...], ...})."""
    groups: Dict[str, List[str]] = {AUTO: [], PARTIAL: [], MANUAL: []}
    for tech in techniques_for(template_id):
        groups[tech.mode].append(tech.name)
    return groups
