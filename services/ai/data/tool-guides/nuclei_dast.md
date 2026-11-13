# nuclei_dast

## When to use

nuclei in DAST and fuzzing mode. It actively fuzzes request parameters and CONFIRMS blind
vulnerabilities — blind SSRF, blind SQL injection, out-of-band RCE and Log4Shell-class issues —
through an out-of-band Interactsh callback the target makes back. Use it to validate a blind lead
a scan surfaced, not for discovery: plain nuclei is the discovery scanner, and nikto, wpscan,
openvas, testssl and ZAP own the other jobs. One `target` is one URL, with the parameters to fuzz
in it.

## Key options

- `target` — required. A single target URL, for example
  `http://juice-shop:3000/rest/products/search?q=1`.
- `opts` — extra nuclei options, for example `-tags ssrf,sqli`. Template-loading flags are
  ignored in DAST mode. This field adds options; the spec names no default it replaces.
- `interactsh_server` — a Reconix-controlled Interactsh server for the out-of-band callbacks. It
  is set by the backend, so leave it out of a proposed action.
- `timeout` — per-call timeout in seconds. The spec names no default; raise it if a fuzzing run
  needs longer.

## Output

One JSON object per finding. Reconix reads it with the same nuclei reader
(`findings/json_mapping.py`, `read_nuclei`), so the finding shape is nuclei's: the template's
`info.name` and the matcher name in the title, the reported `host` as the target, `matched-at` as
the location, the template's own `info.severity` as the severity (`info` becomes `NONE`, a word
the mapping does not know becomes `UNKNOWN`), and its description, remediation and CVE and CWE ids
kept, with the large `request`, `response` and `curl-command` fields left on the tool run's masked
output. `nuclei_dast` is one of the verifying tools named in `schemas/findings.py` (with sqlmap,
dalfox, commix and schemathesis), so a finding from it ranks FIRM with no validation yet;
CONFIRMED comes only from a validation run, and an out-of-band callback is one of the proofs that
schema names. Unreadable output is an error, not an empty scan, and findings are saved only when
the run completed.

## Risk notes

The catalog baseline is `HIGH` and the tool is marked `destructive`, which the harness raises to
at least `HIGH` whatever the baseline says. The two agree here, so every call waits for a person
and is blocked unless the scope's `max_risk` is `HIGH` (HTTP 422). `risk_ops.json` lists no
escalation for it: the tools that are already `HIGH` are gated at their baseline, so a pattern on
them could only repeat it. The spec's own wording is the warning — it SENDS crafted payloads and
may create, modify or delete data, so run it only on an authorised, disposable target, and
confirmation depends on an out-of-band callback to a Reconix-controlled Interactsh server the
backend sets. The scope check (approved targets, exclusions, time window, allowed tools and max
risk) is what keeps those payloads inside the engagement. nuclei_dast is one of the web tools the
scope check knows: when the scope lists allowed ports, the target URL's port — written out, or the
scheme's default 80 or 443 — must be one of them.
