# nikto

## When to use

A web server vulnerability scanner: it checks for more than 6700 known issues — outdated server
software, dangerous files and CGIs, default credentials and server misconfigurations. Use it early
in web recon, on the hosts and ports nmap found, for the low-hanging server problems. It does NOT
exploit, it only reports. For modern CVE-based scanning use nuclei, for a confirmed WordPress site
use wpscan, for the TLS endpoint itself use testssl and for the web scan use ZAP.

## Key options

- `host` — required. The target host or IP, for example `192.168.1.10` or `example.com`.
- `port` — the web server port, documented as defaulting to 80. Use 443 for HTTPS: omit it on an
  HTTPS target and the call goes to port 80.
- `opts` — additional nikto options, for example `-ssl` for HTTPS or `-Tuning 9` for SQLi tests.
  The spec calls these additional and names no default they replace, unlike nuclei's `opts`.
- `timeout` — per-call timeout in seconds. The spec names no default; raise it if a scan needs
  longer.

## Output

A categorized list of findings with severity. Reconix reads that text with `findings/nikto.py`:
one finding per `+` item line, titled from the line with nikto's bracketed item id dropped, and
targeted at the `Target Hostname` and `Target Port` nikto reported, joined as host and port. An
item's severity is `UNKNOWN` unless nikto's own words say otherwise — a missing security header is
`LOW`, and the missing headers of one target are grouped into a single finding instead of one per
header, while a line that names a CVE stays `UNKNOWN` with the CVE id kept on the finding. Header
and banner facts and the summary lines (target info, requests, errors, the retrieved root page)
make no finding. Output that is not nikto's is an unreadable-output error, not a clean scan, and
findings are parsed only when the run completed: nikto is not one of the tools whose non-zero exit
is still read.

## Risk notes

The catalog baseline is `MEDIUM`, so a nikto call waits for a person and anything above the
scope's `max_risk` is blocked with HTTP 422. `risk_ops.json` lists no escalation for nikto, so no
option value lifts a call above that baseline. nikto is marked neither `read_only` nor
`destructive` in the catalog, and the spec's own limit is that it does not exploit, it only
reports. Its requests still reach a live web server, so the scope check — approved targets,
exclusions, time window, allowed tools and max risk — is what keeps the scan on the hosts the
person approved.
