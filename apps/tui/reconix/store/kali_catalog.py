"""The Kali MCP tool catalog, mirrored from tool_specs.json (the source of truth in
Reconix-Kali-MCP). Names, risk and category drive what the AI may suggest at the Scope step
(store/scope_suggest) and what a scope tool may be. Keep it in sync with the Kali repo."""

from typing import Dict, List, NamedTuple


class KaliTool(NamedTuple):
    name: str
    risk: str          # LOW | MEDIUM | HIGH
    category: str
    destructive: bool


# Plumbing/meta tools, not a scan the operator would scope.
PLUMBING = frozenset({
    "zap_start", "zap_stop", "zap_status", "zap_alerts", "zap_report", "zap_context",
    "zap_openapi_import", "tools_info", "run_job", "job_status", "job_result", "run_command",
})

KALI_TOOLS: Dict[str, KaliTool] = {
    'amass': KaliTool('amass', 'LOW', 'recon', False),
    'arjun': KaliTool('arjun', 'MEDIUM', 'web', False),
    'arp_scan': KaliTool('arp_scan', 'MEDIUM', 'network', False),
    'bettercap': KaliTool('bettercap', 'HIGH', 'misc', True),
    'cewl': KaliTool('cewl', 'LOW', 'misc', False),
    'commix': KaliTool('commix', 'HIGH', 'web', True),
    'crunch': KaliTool('crunch', 'LOW', 'password', False),
    'dalfox': KaliTool('dalfox', 'MEDIUM', 'web', False),
    'dnsrecon': KaliTool('dnsrecon', 'LOW', 'network', False),
    'enum4linux': KaliTool('enum4linux', 'MEDIUM', 'recon', False),
    'exiftool': KaliTool('exiftool', 'LOW', 'recon', False),
    'ffuf': KaliTool('ffuf', 'MEDIUM', 'web', False),
    'gitleaks': KaliTool('gitleaks', 'LOW', 'source', False),
    'gobuster': KaliTool('gobuster', 'MEDIUM', 'web', False),
    'grype': KaliTool('grype', 'LOW', 'source', False),
    'hash_identifier': KaliTool('hash_identifier', 'LOW', 'misc', False),
    'hashcat': KaliTool('hashcat', 'LOW', 'password', False),
    'httpx_probe': KaliTool('httpx_probe', 'LOW', 'web', False),
    'hydra': KaliTool('hydra', 'HIGH', 'password', True),
    'impacket': KaliTool('impacket', 'HIGH', 'misc', True),
    'job_result': KaliTool('job_result', 'LOW', 'meta', False),
    'job_status': KaliTool('job_status', 'LOW', 'meta', False),
    'john': KaliTool('john', 'LOW', 'password', False),
    'katana': KaliTool('katana', 'MEDIUM', 'web', False),
    'masscan': KaliTool('masscan', 'MEDIUM', 'network', False),
    'mimikatz': KaliTool('mimikatz', 'HIGH', 'misc', True),
    'mitmproxy': KaliTool('mitmproxy', 'LOW', 'misc', False),
    'msf_info': KaliTool('msf_info', 'LOW', 'metasploit', False),
    'msf_resource': KaliTool('msf_resource', 'HIGH', 'metasploit', True),
    'msf_search': KaliTool('msf_search', 'LOW', 'metasploit', False),
    'msfconsole': KaliTool('msfconsole', 'HIGH', 'metasploit', True),
    'msfdb': KaliTool('msfdb', 'LOW', 'metasploit', False),
    'msfvenom': KaliTool('msfvenom', 'MEDIUM', 'metasploit', False),
    'netcat': KaliTool('netcat', 'HIGH', 'network', True),
    'newman': KaliTool('newman', 'MEDIUM', 'api', False),
    'nikto': KaliTool('nikto', 'MEDIUM', 'web', False),
    'nmap': KaliTool('nmap', 'LOW', 'network', False),
    'nuclei': KaliTool('nuclei', 'MEDIUM', 'web', False),
    'nuclei_dast': KaliTool('nuclei_dast', 'HIGH', 'web', True),
    'onesixtyone': KaliTool('onesixtyone', 'MEDIUM', 'network', False),
    'openvas': KaliTool('openvas', 'HIGH', 'openvas', False),
    'osv_scanner': KaliTool('osv_scanner', 'LOW', 'source', False),
    'proxychains': KaliTool('proxychains', 'MEDIUM', 'misc', False),
    'responder': KaliTool('responder', 'HIGH', 'misc', True),
    'run_command': KaliTool('run_command', 'HIGH', 'meta', False),
    'run_job': KaliTool('run_job', 'LOW', 'meta', False),
    'rustscan': KaliTool('rustscan', 'MEDIUM', 'network', False),
    'schemathesis': KaliTool('schemathesis', 'MEDIUM', 'api', False),
    'searchsploit': KaliTool('searchsploit', 'LOW', 'recon', False),
    'semgrep': KaliTool('semgrep', 'LOW', 'source', False),
    'smbclient': KaliTool('smbclient', 'MEDIUM', 'recon', False),
    'sonar_scan': KaliTool('sonar_scan', 'LOW', 'source', False),
    'sqlmap': KaliTool('sqlmap', 'HIGH', 'web', True),
    'subfinder': KaliTool('subfinder', 'LOW', 'recon', False),
    'syft': KaliTool('syft', 'LOW', 'source', False),
    'tcpdump': KaliTool('tcpdump', 'MEDIUM', 'network', False),
    'testssl': KaliTool('testssl', 'LOW', 'web', False),
    'theHarvester': KaliTool('theHarvester', 'LOW', 'recon', False),
    'tools_info': KaliTool('tools_info', 'LOW', 'meta', False),
    'trivy': KaliTool('trivy', 'LOW', 'source', False),
    'tshark': KaliTool('tshark', 'MEDIUM', 'network', False),
    'wfuzz': KaliTool('wfuzz', 'MEDIUM', 'web', False),
    'whatweb': KaliTool('whatweb', 'LOW', 'web', False),
    'wpscan': KaliTool('wpscan', 'MEDIUM', 'web', False),
    'zap_active_scan': KaliTool('zap_active_scan', 'HIGH', 'zap', True),
    'zap_ajax_spider': KaliTool('zap_ajax_spider', 'MEDIUM', 'zap', False),
    'zap_alerts': KaliTool('zap_alerts', 'LOW', 'zap', False),
    'zap_context': KaliTool('zap_context', 'LOW', 'zap', False),
    'zap_openapi_import': KaliTool('zap_openapi_import', 'LOW', 'zap', False),
    'zap_report': KaliTool('zap_report', 'LOW', 'zap', False),
    'zap_scan': KaliTool('zap_scan', 'HIGH', 'zap', True),
    'zap_spider': KaliTool('zap_spider', 'MEDIUM', 'zap', False),
    'zap_start': KaliTool('zap_start', 'LOW', 'zap', False),
    'zap_status': KaliTool('zap_status', 'LOW', 'zap', False),
    'zap_stop': KaliTool('zap_stop', 'LOW', 'zap', False),
}


def suggestible(categories: List[str]) -> List[KaliTool]:
    """Catalog tools the AI may suggest for these categories: not destructive, not plumbing,
    not meta. The operator still ticks to add them; the harness gates each by risk at run."""
    wanted = set(categories)
    return [t for t in KALI_TOOLS.values() if t.category in wanted and not t.destructive
            and t.category != "meta" and t.name not in PLUMBING]


def catalog_name(name: str) -> str:
    """The catalog name for `name` (case-insensitive), or \"\" when it is not a Kali tool."""
    if name in KALI_TOOLS:
        return name
    low = name.strip().lower()
    return low if low in KALI_TOOLS else ""


def tool_risk(name: str) -> str:
    tool = KALI_TOOLS.get(catalog_name(name))
    return tool.risk if tool else ""


# Each suggestible tool's job (role) and a one-line purpose, so the scope can explain what a
# tool is for ("ffuf — brute-force hidden paths") and offer ONE choice per job (two tools that
# do the same thing collapse to a single pick).
ROLE: Dict[str, str] = {
    "katana": "crawl", "zap_spider": "crawl", "zap_ajax_spider": "crawl",
    "gobuster": "path-bruteforce", "ffuf": "path-bruteforce", "wfuzz": "path-bruteforce",
    "httpx_probe": "fingerprint", "whatweb": "fingerprint",
    "nikto": "web-scan", "nuclei": "vuln-scan", "wpscan": "cms-scan",
    "arjun": "param-discovery", "dalfox": "xss",
    "nmap": "port-scan", "masscan": "port-scan", "rustscan": "port-scan",
    "testssl": "tls", "onesixtyone": "snmp", "enum4linux": "smb",
    "schemathesis": "api-fuzz", "newman": "api-replay",
    "semgrep": "static-analysis", "gitleaks": "secrets",
    "trivy": "dependencies", "grype": "dependencies", "osv_scanner": "dependencies",
    "syft": "sbom",
}

PURPOSE: Dict[str, str] = {
    "katana": "crawl the site to find linked paths",
    "zap_spider": "crawl the site with OWASP ZAP",
    "zap_ajax_spider": "crawl a JavaScript app with OWASP ZAP",
    "gobuster": "brute-force hidden paths and files",
    "ffuf": "brute-force hidden paths and files",
    "wfuzz": "brute-force paths and parameters",
    "httpx_probe": "probe HTTP and detect the stack",
    "whatweb": "fingerprint the web technologies",
    "nikto": "scan the web server for known issues",
    "nuclei": "scan for known vulnerabilities",
    "wpscan": "scan a WordPress site",
    "arjun": "discover hidden parameters",
    "dalfox": "test parameters for XSS",
    "nmap": "scan ports and detect services",
    "masscan": "fast port scan of a range",
    "rustscan": "fast port scan, then nmap",
    "testssl": "check TLS/SSL configuration",
    "onesixtyone": "scan for SNMP",
    "enum4linux": "enumerate SMB/Windows shares and users",
    "schemathesis": "fuzz the API from its schema",
    "newman": "replay a Postman collection",
    "semgrep": "static analysis of the code",
    "gitleaks": "find leaked secrets",
    "trivy": "scan dependencies for known issues",
    "grype": "scan dependencies for known issues",
    "osv_scanner": "scan dependencies for known/malicious packages",
    "syft": "build a software bill of materials",
}


def tool_role(name: str) -> str:
    return ROLE.get(catalog_name(name), "")


def tool_purpose(name: str) -> str:
    return PURPOSE.get(catalog_name(name), "")
