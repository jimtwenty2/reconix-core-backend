# zap_spider

## When to use

Crawls (spiders) a web application with ZAP to enumerate its URLs, forms and endpoints. Use it as
the FIRST ZAP step, to map the application before active scanning: ZAP can only actively scan URLs
that are already in its site tree, and this is what puts them there. For a complete scan in one call
use zap_scan, which spiders, waits for passive scanning and then actively scans; use this tool when
you want the two phases apart. On a JavaScript-heavy or single-page target, zap_ajax_spider reaches
the URLs the traditional spider misses.

## Key options

- `url` — required — the target URL to spider, for example `http://192.168.1.10`.
- `recurse` — recurse into discovered URLs (default `true`).
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).
- `timeout` — max seconds to wait for the spider (default `300`).

## Output

The number of URLs discovered, and a sample of them. Reconix has no reader for zap_spider, so none
of those URLs become findings; the masked output is kept on the tool run. The ZAP output Core parses
into findings is zap_scan's SARIF document.

## Risk notes

The catalog baseline is `MEDIUM`, the entry is not marked destructive, and `risk_ops.json` has no
zap_* entry, so a call stays `MEDIUM` whatever you pass it. Under S4 that waits for a person to
approve; `LOW` would run now, and an action above the scope's `max_risk` is blocked. The `url` must
sit inside the approved scope (S3). The crawl can be slow on first use, because of the one-time
daemon start: call it directly and wait, raise `timeout`, or start it through `run_job`, which names
zap_spider as a slow scan and returns a job id to poll.
