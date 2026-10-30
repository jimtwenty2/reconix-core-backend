"""10 saved tool outputs, two per tool, each with the finding a parser made from it.

The outputs are short real-shaped excerpts. Every evidence line is copied from
its output, and every target is inside the test scope (172.20.0.0/24 and
http://juice-shop:3000/), so a good next step passes the harness.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Case:
    name: str
    output: str
    finding: dict[str, Any]
    evidence: str  # a line copied from output
    next_step: dict[str, Any] | None


def finding(code: str, title: str, target: str, severity: str, **ids: list[str]) -> dict:
    return {
        "code": code,
        "title": title,
        "target": target,
        "description": title,
        "severity_status": severity,
        "finding_status": "OPEN",
        "cvss_score": None,
        "cwe_ids": ids.get("cwe_ids", []),
        "owasp_id": ids.get("owasp_id", []),
        "cve_ids": ids.get("cve_ids", []),
    }


NMAP_CHECK = {"tool": "NMAP", "target": "172.20.0.5", "arguments": ["-sV", "-p", "21"]}
NUCLEI_CHECK = {"tool": "NUCLEI", "target": "http://juice-shop:3000/", "arguments": []}

CASES = [
    Case(
        "nmap_ftp_anonymous",
        '<port protocol="tcp" portid="21"><state state="open"/>'
        '<service name="ftp" product="vsftpd" version="2.3.4"/>\n'
        '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>',
        finding("RCX-001", "Anonymous FTP login", "172.20.0.5", "MEDIUM", cwe_ids=["CWE-287"]),
        "Anonymous FTP login allowed (FTP code 230)",
        NMAP_CHECK,
    ),
    Case(
        "nmap_old_openssh",
        '<port protocol="tcp" portid="22"><state state="open"/>\n'
        '<service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1"/></port>',
        finding(
            "RCX-002", "Outdated OpenSSH 4.7p1", "172.20.0.5", "MEDIUM", cve_ids=["CVE-2008-5161"]
        ),
        '<service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1"/></port>',
        None,
    ),
    Case(
        "nuclei_exposed_metrics",
        '{"template-id":"prometheus-metrics","info":{"name":"Prometheus Metrics",'
        '"severity":"medium"},"matched-at":"http://juice-shop:3000/metrics"}',
        finding(
            "RCX-003",
            "Exposed Prometheus metrics",
            "http://juice-shop:3000/metrics",
            "MEDIUM",
            cwe_ids=["CWE-200"],
            owasp_id=["A01:2021"],
        ),
        '"matched-at":"http://juice-shop:3000/metrics"',
        NUCLEI_CHECK,
    ),
    Case(
        "nuclei_missing_csp",
        '{"template-id":"http-missing-security-headers:content-security-policy",'
        '"info":{"severity":"info"},"matched-at":"http://juice-shop:3000/"}',
        finding(
            "RCX-004",
            "Missing Content-Security-Policy header",
            "http://juice-shop:3000/",
            "NONE",
            cwe_ids=["CWE-693"],
            owasp_id=["A05:2021"],
        ),
        "http-missing-security-headers:content-security-policy",
        None,
    ),
    Case(
        "zap_sql_injection",
        '{"alert":"SQL Injection","riskdesc":"High (Medium)","cweid":"89",'
        '"uri":"http://juice-shop:3000/rest/products/search?q=%27"}',
        finding(
            "RCX-005",
            "SQL injection in product search",
            "http://juice-shop:3000/rest/products/search",
            "HIGH",
            cwe_ids=["CWE-89"],
            owasp_id=["A03:2021"],
        ),
        '"uri":"http://juice-shop:3000/rest/products/search?q=%27"',
        NUCLEI_CHECK,
    ),
    Case(
        "zap_reflected_xss",
        '{"alert":"Cross Site Scripting (Reflected)","riskdesc":"High (Medium)",'
        '"cweid":"79","param":"q","uri":"http://juice-shop:3000/search?q=x"}',
        finding(
            "RCX-006",
            "Reflected XSS in search",
            "http://juice-shop:3000/search",
            "HIGH",
            cwe_ids=["CWE-79"],
            owasp_id=["A03:2021"],
        ),
        '"alert":"Cross Site Scripting (Reflected)"',
        NUCLEI_CHECK,
    ),
    Case(
        "semgrep_eval",
        '{"check_id":"javascript.lang.security.audit.eval-detected",'
        '"path":"routes/b2bOrder.ts","start":{"line":23},'
        '"extra":{"lines":"vm.runInContext(\'safeEval(orderLinesData)\', sandbox)"}}',
        finding(
            "RCX-007",
            "Code evaluated from user input",
            "routes/b2bOrder.ts",
            "HIGH",
            cwe_ids=["CWE-95"],
        ),
        "vm.runInContext('safeEval(orderLinesData)', sandbox)",
        None,
    ),
    Case(
        "semgrep_hardcoded_jwt_secret",
        '{"check_id":"javascript.jsonwebtoken.security.jwt-hardcode",'
        '"path":"lib/insecurity.ts","start":{"line":40},'
        '"extra":{"lines":"jwt.sign(user, privateKey, { algorithm: [MASKED:private_key] })"}}',
        finding(
            "RCX-008",
            "JWT signed with a key in the code",
            "lib/insecurity.ts",
            "HIGH",
            cwe_ids=["CWE-798"],
            owasp_id=["A07:2021"],
        ),
        '"check_id":"javascript.jsonwebtoken.security.jwt-hardcode"',
        None,
    ),
    Case(
        "gitleaks_aws_key",
        '{"RuleID":"aws-access-token","File":"config/deploy.yml","StartLine":12,'
        '"Secret":"[MASKED:aws_access_key]","Commit":"9f1c2e7"}',
        finding(
            "RCX-009",
            "AWS access key in the repository",
            "config/deploy.yml",
            "CRITICAL",
            cwe_ids=["CWE-798"],
        ),
        '"RuleID":"aws-access-token","File":"config/deploy.yml"',
        None,
    ),
    Case(
        "gitleaks_generic_api_key",
        '{"RuleID":"generic-api-key","File":"frontend/src/environments/environment.ts",'
        '"StartLine":5,"Secret":"[MASKED:api_key]","Commit":"41ab0d3"}',
        finding(
            "RCX-010",
            "API key in the frontend code",
            "frontend/src/environments/environment.ts",
            "HIGH",
            cwe_ids=["CWE-798"],
        ),
        '"RuleID":"generic-api-key"',
        None,
    ),
]
