# testssl

## When to use

Checks TLS and SSL protocols, ciphers, certificates and known vulnerabilities with testssl.sh. Use
it against an HTTPS endpoint, as host:443, once nmap has shown the port open. It answers the TLS
question only: for the application behind that endpoint use nuclei or ZAP, for the web server's
known issues use nikto, and for a confirmed WordPress site use wpscan.

## Key options

- `target` — required. A target host, host:port, or URL, for example `example.com:443`.
- `opts` — additional testssl.sh options, for example `-U` for all vulnerabilities. The spec calls
  these additional and names no default they replace, unlike nuclei's `opts`.
- `timeout` — per-call timeout in seconds. The spec names no default; raise it if a full
  vulnerability pass needs longer.

## Output

Protocol and cipher support and a vulnerability rundown (Heartbleed, ROBOT and the rest). Reconix
reads the text with `findings/testssl.py`, line by line, and takes testssl's own verdict as the
severity — it never invents one. A line testssl marks OK is dropped. A protocol offered that
testssl calls deprecated becomes `MEDIUM`. A vulnerability line whose verdict is VULNERABLE takes
testssl's own rating word (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and `UNKNOWN` when the line gives
none, with any CVE in it kept. A certificate line marked NOT ok — self-signed, expired, a missing
SubjectAltName, a broken chain of trust — becomes `LOW`. Every finding carries OWASP `A02:2021`,
the remediation to disable weak protocols and ciphers and fix the certificate chain, the testssl
line as evidence, and the `-->>` target line as its target. Output that is not testssl's is an
unreadable-output error, not a clean endpoint. One limit: each line is read on its own, so a
verdict testssl wraps onto a second line is attributed to that line rather than to the labelled
line with the CVE; single-line verdicts are read correctly.

## Risk notes

The catalog baseline is `LOW` and the tool is marked `read_only`, so a testssl call runs now, with
no person waiting to approve it. `LOW` is the bottom of the harness's risk order, so nothing about
a plain testssl call can be above the scope's `max_risk`; the scope check still decides — the
target must sit inside the approved targets and exclusions and the time window, and testssl must
be one of the scope's allowed tools. `risk_ops.json` lists no escalation for testssl, so no option
value raises a call above `LOW`.
