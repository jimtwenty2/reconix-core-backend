# zap_ajax_spider

## When to use

Crawls a JavaScript-heavy or single-page application with OWASP ZAP's AJAX spider, which drives a
browser engine to reach URLs the traditional spider misses. Use it on an SPA target where zap_spider
enumerates too little, and before any active work, since ZAP can only actively scan URLs already in
its site tree. It runs with the bundled HtmlUnit engine, so no external browser is needed; install
Firefox or Chrome for full SPA rendering. Give it a context and a user to crawl the authenticated
pages.

## Key options

- `url` — required — the target URL to crawl, for example `http://juice-shop:3000`.
- `context_name` — crawl within this context.
- `user_name` — crawl as this context user; requires `context_name`.
- `max_depth` — the maximum crawl depth.
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).
- `timeout` — max seconds to wait for the crawl (default `300`).

## Output

The crawl status and the number of URLs found. Reconix has no reader for zap_ajax_spider, so none of
those URLs become findings; the masked output is kept on the tool run. The URLs are added for the
steps that follow, and the ZAP output Core parses into findings is zap_scan's SARIF document.

## Risk notes

The catalog baseline is `MEDIUM`, the entry is not marked destructive, and `risk_ops.json` has no
zap_* entry, so a call stays `MEDIUM` whatever you pass it. Under S4 that waits for a person to
approve; `LOW` would run now, and an action above the scope's `max_risk` is blocked. The crawl
drives a browser engine at a live target, so the `url`, and any context and user it crawls as, must
be inside the approved scope (S3). The wait is capped by `timeout`, 300 seconds by default; raise it
for a deep site.
