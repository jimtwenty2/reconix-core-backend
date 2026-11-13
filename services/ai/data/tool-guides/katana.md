# katana

## When to use

Crawl a web application to enumerate its endpoints and URLs. Use it early on a web target, after a
fingerprint has shown the service answers, to get the URL list the rest of the web test works
from; set `headless` for JavaScript-heavy or SPA targets. A crawl lists URLs and says nothing
about them, so the neighbours do the testing: arjun looks for undocumented parameters on a URL it
returns, ffuf and wfuzz fuzz those parameters or a path, gobuster brute-forces paths and
subdomains a crawl does not reach, and sqlmap, commix and dalfox test a parameter for SQL
injection, command injection and XSS.

## Key options

- `url` — required. An absolute HTTP(S) target URL.
- `depth` — the maximum crawl depth; the documented default is 3.
- `headless` — render JavaScript with Chromium; the documented default is false. Set it for a
  JavaScript-heavy or SPA target.
- `headers` — HTTP headers, for example Authorization or Cookie. A credential sent this way is
  masked before anything is saved, logged, shown or sent to the AI (S8).
- `rate_limit` — requests per second; the documented default is 5. It is the knob that sets how
  hard the crawl presses the target.
- `opts` — additional Katana options; quoted values are supported.
- `timeout` — the total execution timeout in seconds; the documented default is 300. A deep crawl
  of a large application can need more.

## Output

The spec's own words: discovered URLs, one per line. Reconix takes the lines that start with
`http` and reads them with `findings/paths.py`. Paths are grouped, not one finding per URL: one
`NONE` summary finding per run counts them and keeps the URLs as evidence, capped at 100
(`MAX_EVIDENCE`), and then one finding per kind of sensitive path name. Severity comes from the
name alone and is never guessed higher: a URL that would leak a secret, a key, source or data is
HIGH, an admin, configuration, backup, history, debug or exposed file store is MEDIUM, and
anything a name only hints at stays LOW.

## Risk notes

The catalog baseline is `MEDIUM`, so under S4 a crawl waits for a person, and a call above the
scope's `max_risk` is BLOCKED with HTTP 422. `risk_ops.json` defines no patterns for katana, so
the baseline is the whole story, and it is not marked destructive: the spec's own description is a
crawl that enumerates endpoints and URLs. `depth` and `rate_limit` are what keep such a run small
and slow enough for the target. The target URL must be inside the approved scope: S3 lets nothing
run outside the approved targets, exclusions, time window, allowed tools and max risk.
