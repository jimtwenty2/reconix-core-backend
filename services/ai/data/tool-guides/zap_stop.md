# zap_stop

## When to use

Shuts down the OWASP ZAP daemon this server started, to free resources when you are finished
scanning. It is the last step of a ZAP sequence: zap_alerts and zap_report read what the daemon has
recorded, and zap_scan, zap_spider and zap_ajax_spider are what put anything there, so all of them
come first. Stopping the daemon does not end the ability to scan — every zap_* tool auto-starts it
again — it only pays the one-time daemon start a second time.

## Key options

Nothing is required.

- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

A confirmation. Reconix has no reader for zap_stop, so nothing is parsed into findings; the masked
output is kept on the tool run. zap_status afterwards reports whether the daemon is still running
and reachable.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only` and is not destructive, and
`risk_ops.json` has no zap_* entry, so no argument value raises a call above `LOW`. Under S4 a `LOW`
action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for one, and an action above
the scope's `max_risk` is blocked. It touches the daemon rather than a target, so it is the cheap
step to finish a sequence with.
