# zap_scan

## When to use

The primary ZAP tool: a full web application scan in one call — spider, wait for passive scanning,
active scan, then return the findings. Take it over zap_spider plus zap_active_scan unless you need
finer control of the two phases. Core's ZAP is this tool: the name `zap` finds the same reader as
`zap_scan`. It is intrusive, so authorized targets only.

## Key options

- `url` — required — the target URL to scan, for example `http://192.168.1.10`.
- `recurse` — recurse into discovered URLs (default `true`).
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).
- `timeout` — max seconds for the active scan phase (default `900`).

## Output

A SARIF JSON document (envelope format `sarif`) of the alerts found for this target, scoped to it,
with no scan-progress text; zero alerts still returns valid SARIF with an empty `results` list.
Reconix reads that document into findings, as evidence kind `zap_alert`: one finding per rule and
location, titled from the rule, targeted at the alert's URI, with the rule's CWE ids and remediation
and the result itself kept as evidence. Severity comes from the alert's own security-severity score
when it gives one, else from its SARIF level — `error` HIGH, `warning` MEDIUM, `note` LOW, `none`
NONE, which is ZAP's Informational — and a level SARIF does not define is UNKNOWN, never guessed.
ZAP's request and response bodies stay on the tool run, not in the evidence. Empty output, or output
that is not SARIF, is an unreadable-output error, not a clean scan.

## Risk notes

The catalog baseline is `HIGH` and the entry is marked `destructive`, which the harness raises to at
least `HIGH` whatever the baseline says. Under S4 a `HIGH` action waits for a person, and a scope
whose `max_risk` is below `HIGH` blocks it; `risk_ops.json` has no zap_* entry, so no argument
escalates a call further. The active scan phase sends real attack payloads, so `url` must be an
authorized target inside the approved scope (S3). It is slow — several minutes, plus a one-time
daemon start of about one to two minutes on first use: call it directly and wait, raising `timeout`
for large sites, or start it through `run_job`, which names zap_scan and returns a job id to poll.
zap_scan is one of the web tools the scope check knows: when the scope lists allowed ports, the
target URL's port — written out, or the scheme's default 80 or 443 — must be one of them.
