# dalfox

## When to use

A fast parameter-analysis XSS scanner. Use it against a URL with an injectable parameter to find
reflected and DOM XSS, normally after a crawl or a parameter discovery has shown which parameters
the endpoint takes. katana supplies the URLs and arjun the undocumented parameters to aim at. For
SQL injection on the same parameter use sqlmap; for command injection use commix.

## Key options

- `url` — required. An absolute HTTP(S) target URL.
- `method` — the HTTP method; the documented default is GET.
- `headers` — HTTP headers, for example Authorization or Cookie. A credential sent this way is
  masked before anything is saved, logged, shown or sent to the AI (S8).
- `body` — optional. A raw request body.
- `parameters` — optional. The parameter names to test, instead of leaving dalfox to analyse the
  URL's own parameters.
- `delay` — the delay between requests in milliseconds; the documented default is 0. Note the unit:
  katana and arjun take seconds here.
- `rate_limit` — global requests per second; the documented default is unlimited.
- `opts` — additional Dalfox options; quoted values are supported.
- `timeout` — the total execution timeout in seconds; the documented default is 300.

## Output

The spec's own words: proofs-of-concept for confirmed XSS. Reconix reads that text with
`findings/dalfox.py`, which turns only the tagged proof-of-concept lines into findings: a verified
cross-site scripting hit is HIGH with CWE-79 and A03:2021, a reflected parameter that was not
confirmed is MEDIUM. The tagged line itself is kept as evidence with the URL as its location, and
the injected parameter marker in that URL is evidence, not a secret. A scan that finds nothing
makes no finding, and text that is not dalfox's is an unreadable-output error rather than a clean
run. dalfox exits non-zero precisely when it finds issues, so Core still reads the findings from a
run that came back FAILED or TIMED_OUT but left output to read.

## Risk notes

The catalog baseline is `MEDIUM`, so under S4 a dalfox run waits for a person, and a call above the
scope's `max_risk` is BLOCKED with HTTP 422; the risk check also holds any call that validates a
finding at MEDIUM at least. `risk_ops.json` defines no patterns for dalfox, and it is not marked
destructive, but it does send payloads: the spec's output is a proof-of-concept for each confirmed
XSS, so injection goes into the target's parameters and a hit comes back in its response. Its
payloads look like markup, and secrets are still masked before anything is saved, logged, shown or
sent to the AI (S8). The target URL must be inside the approved scope: S3 lets nothing run outside
the approved targets, exclusions, time window, allowed tools and max risk.
