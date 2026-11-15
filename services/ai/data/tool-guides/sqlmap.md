# sqlmap

## When to use

Automated SQL injection detection, exploitation and data extraction. Use it on a URL parameter that
may be injectable, normally after a crawl or a fingerprint has shown which parameters the endpoint
takes. It handles detection, database fingerprinting, data dumping and even OS shell access through
SQLi, and in Reconix its reader is written for the validation phase, where it confirms a weakness
an earlier scan flagged. For command injection rather than SQL use commix; for XSS use dalfox.

## Key options

- `url` — required. The target URL with its parameters, the one holding the parameter to test.
- `opts` — additional sqlmap options. The documented default is `--random-agent`, and `--batch` is
  always applied, so a non-interactive run never waits at a prompt.
- `timeout` — per-call timeout in seconds. Fingerprinting the database and extracting data takes
  longer than a detection pass on its own, so raise it.

## Output

The spec's own words: it confirms injectable parameters, the database type and version, and
extracted data. Reconix reads that text with `findings/sqlmap.py`. A confirmed injection prints an
injection-point block — a `Parameter:` line naming the parameter and its place, the injection
`Type:` lines under it, then the `back-end DBMS` — and becomes one finding per injectable
parameter, HIGH with CWE-89 and A03:2021, the parameter line and its injection types kept as
evidence. A run where no tested parameter looks injectable makes no finding, and text that is not
sqlmap's is an unreadable-output error rather than a clean run. sqlmap exits non-zero precisely
when it finds issues, so Core still reads the findings from a run that came back FAILED or
TIMED_OUT but left output to read. Dumped data can hold credentials, and secrets are masked before
anything is saved, logged, shown or sent to the AI (S8).

## Risk notes

The catalog baseline is `HIGH` and sqlmap is marked `destructive`; the harness risk check pushes a
destructive tool to at least HIGH whatever the baseline says, so it is HIGH either way. Under S4
that means every sqlmap call waits for a person, and a call above the scope's `max_risk` is BLOCKED
with HTTP 422. `risk_ops.json` defines no patterns for sqlmap: an already-high tool is gated at its
baseline, so a pattern on it could not raise it further. The spec is plain about what it sends —
detection, exploitation, data dumping and OS shell access through SQLi — so this is not a read-only
probe, and `opts` should stay at what the test needs. sqlmap is not a free-shell tool, so S6 still
blocks control and shell characters in its arguments. The target URL must be inside the approved
scope: S3 lets nothing run outside the approved targets, exclusions, time window, allowed tools and
max risk.
