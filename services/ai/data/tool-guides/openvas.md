# openvas

## When to use

The OpenVAS/Greenbone (GVM) network vulnerability scanner. It runs an authenticated GMP scan (Full
and Fast) against one host or IP and returns that host's GVM report: the broad, slow sweep of a
network target. Use it after nmap has mapped the host. For fast template-based web and service
vulnerability scanning the spec tells you to prefer nuclei; nikto covers a web server's known
issues, testssl one TLS endpoint, wpscan a confirmed WordPress site and ZAP the web scan.

## Key options

- `target` — required. A bare host or IP to scan, for example `192.168.210.129`. NOT a URL.
- `opts` — extra args for the openvas-scan helper, for example an alternate scan-config name. The
  spec names no default that setting it replaces; the scan it describes is an authenticated GMP
  scan (Full and Fast).
- `timeout` — per-call timeout in seconds, and the spec warns that full scans are slow. A full scan
  takes many minutes, so raise it.

## Output

The GVM report XML. Reconix has no reader for openvas — it is not in the `READERS` table in
`services/findings.py` — so nothing is parsed into finding rows and no severity is assigned. The
masked output is still kept on the tool run, and that is where the report is read: a run that
saved no findings is not a clean host, it is a run no reader parsed. Findings are attached to a run
only when it completed, and openvas is not one of the tools whose non-zero exit is still read, so
a scan cut short by its own timeout leaves the report on the run and nothing else.

## Risk notes

The catalog baseline is `HIGH`, so every openvas call waits for a person and is blocked unless the
scope's `max_risk` is `HIGH` (HTTP 422). openvas is marked neither `destructive` nor `read_only`,
and `risk_ops.json` lists no escalation for it: the tools that are already `HIGH` are gated at
their baseline, so a pattern on them could only repeat it. The stack has a precondition the spec
names — OpenVAS is a daemon stack with large detection feeds that sync at runtime, and the
one-time `openvas-bootstrap` must have run first, or the call returns an actionable error instead
of a report. A scan then runs for many minutes against one host, so the approval and the scope
check (targets, exclusions, time window, allowed tools, max risk) are what keep it on the host the
person approved.
