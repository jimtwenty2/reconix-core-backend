# nuclei

## When to use

The primary web and service vulnerability scanner: a template-based scanner with thousands of
community-maintained YAML templates that detects CVEs, misconfigurations, exposed panels and
default credentials. Use it after nmap has shown which hosts and ports are up. nikto is the early
sweep of a web server's known issues, wpscan is for a confirmed WordPress site, openvas is the
slow full network scan and ZAP the web scan; nuclei is the one the catalog calls the primary
scanner. To confirm a blind lead instead of looking for new ones, use nuclei_dast.

## Key options

- `target` — required. A single target URL, IP or hostname, for example
  `http://juice-shop:3000`. Not a file list.
- `opts` — nuclei options. Setting it REPLACES the default `-severity medium,high,critical`, so
  include what you still want, for example `-severity critical,high -tags cve`. Omit it and only
  medium, high and critical matches come back.
- `timeout` — per-call timeout in seconds. A full scan can take a few minutes: call nuclei
  directly and wait for the result, and raise this if it needs longer.

## Output

One JSON object per finding, as JSON lines. Reconix reads them with the nuclei reader
(`findings/json_mapping.py`, `read_nuclei`): one finding per template match, titled from the
template's `info.name` plus the matcher name, targeted at the reported `host`, located at
`matched-at`, and deduped on template id, matcher name and matched-at. The severity is the
template's own `info.severity` — `info` becomes `NONE`, and a word the mapping does not know
becomes `UNKNOWN`, never a guess — with the template's description, remediation and CVE and CWE
ids kept on the finding. Several `NONE` matches that share a title (ten missing security headers
from one template) are grouped into one finding that keeps up to 100 matcher lines; anything
above `NONE` keeps its own finding. The `request`, `response` and `curl-command` fields are too
large for evidence and stay on the tool run's masked output. Output that does not parse is an
unreadable-output error, not a clean scan with nothing in it, and findings are parsed only when
the run completed: nuclei is not one of the tools whose non-zero exit is still read. Until a
validation or a second tool agrees, a match is one scanner's unvalidated finding.

## Risk notes

The catalog baseline is `MEDIUM`, so a nuclei call waits for a person and runs only on an
approval; anything above the scope's `max_risk` is blocked with HTTP 422. `risk_ops.json` lists no
escalation for nuclei, so no `opts` value lifts a call above that baseline — the approval is the
gate whatever the templates do. The catalog marks nuclei neither `read_only` nor `destructive`.
Its templates are sent to the target over the network, so the scope check is what keeps the scan
inside the approved targets, exclusions, time window, allowed tools and max risk, and only tools
in the Kali catalog may run at all. nuclei is one of the web tools the scope check knows: when the
scope lists allowed ports, the target URL's port — written out, or the scheme's default 80 or 443 —
must be one of them.
