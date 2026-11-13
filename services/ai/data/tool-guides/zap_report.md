# zap_report

## When to use

Generates an OWASP ZAP report for the findings collected so far and saves it to disk. Use it at the
end of a ZAP sequence, once zap_scan, or zap_spider and zap_active_scan, have put alerts in the
daemon, and when you want a document rather than the list zap_alerts gives. Reports cover every site
the daemon has scanned unless `sites` narrows them, so name the site when the daemon has seen more
than one.

## Key options

Nothing is required.

- `template` — the report template (default `sarif-json`). Working templates: `traditional-html`,
  `traditional-md`, `modern`, `high-level-report`, `sarif-json`.
- `report_dir` — the directory to write the report to (default `/tmp`).
- `file_name` — the report file name, without an extension (default `zap-report`).
- `sites` — limit the report to this site, as `scheme://host[:port]` (default: all sites the daemon
  has scanned).
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

For `sarif-json`, the report body itself (envelope format `sarif`); for every other template, the
path to the generated file and the alert count. Reconix has no reader for zap_report — the SARIF
reader is wired to zap_scan — so a report does not become findings on its own; its masked output is
kept on the tool run.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only`, and it is not flagged destructive
even though it saves a file, so nothing raises it; `risk_ops.json` has no zap_* entry either. Under
S4 a `LOW` action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for one, and an
action above the scope's `max_risk` is blocked. The report covers the findings collected so far: it
does not scan anything itself, only the earlier steps did that.
