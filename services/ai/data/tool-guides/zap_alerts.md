# zap_alerts

## When to use

Lists the security alerts, the findings, that OWASP ZAP has recorded, optionally filtered by target
base URL and risk level. Use it after a spider or an active scan to review results without running
another scan, and before zap_report when you want the list rather than a document. It reads what the
daemon already holds, so it adds nothing to the site tree and sends no attack payloads.

## Key options

Nothing is required; every option narrows or limits the list.

- `base_url` — filter alerts to this target base URL.
- `risk` — filter by risk: `High`, `Medium`, `Low` or `Informational`.
- `limit` — max alerts to display (default `100`).
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

The alerts, each with its risk, confidence, affected URL, parameter and evidence. Reconix has no
reader for zap_alerts, so this list does not become findings; the masked output is kept on the tool
run for a person to read. The ZAP output Core parses into findings is zap_scan's SARIF document.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only` and is not destructive, and
`risk_ops.json` has no zap_* entry, so no argument raises a call above `LOW`. Under S4 a `LOW`
action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for one, and an action above
the scope's `max_risk` is blocked. The filter options choose which recorded alerts you see; they do
not aim a scan at anything new.
