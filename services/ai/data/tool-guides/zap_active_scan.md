# zap_active_scan

## When to use

Runs a ZAP active scan against a target URL. You MUST run zap_spider on the URL first, because ZAP
can only actively scan URLs already in its site tree, or just use zap_scan, which does both in one
call. Use this tool when you want the crawl and the attack phase as separate steps, each approved on
its own, and zap_alerts afterwards to review what the scan recorded.

## Key options

- `url` — required — the target URL to actively scan, for example `http://192.168.1.10`.
- `recurse` — scan URLs discovered under the target (default `true`).
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).
- `timeout` — max seconds to wait for the scan (default `600`).

## Output

Scan progress and the alerts discovered. Reconix has no reader for zap_active_scan, so those alerts
are not parsed into findings; the masked output is kept on the tool run. The ZAP output Core reads
into findings is zap_scan's SARIF document, so use zap_scan when you want findings from one call.

## Risk notes

The catalog baseline is `HIGH` and the entry is marked `destructive`, which the harness raises to at
least `HIGH` whatever the baseline says; here it is `HIGH` already. Under S4 that waits for a
person, and a scope whose `max_risk` is below `HIGH` blocks the call. `risk_ops.json` has no zap_*
entry, so nothing escalates it further. Active scanning sends real attack payloads (SQLi, XSS, path
traversal) and is intrusive: only systems you are authorized to test, inside the approved scope
(S3). It is slow: call it directly and wait, raising `timeout` if needed, or start it through
`run_job`, which names zap_active_scan and returns a job id to poll.
