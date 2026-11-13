# zap_status

## When to use

Checks whether the OWASP ZAP daemon is running and reachable, and reports its version. Use it at the
start of a ZAP sequence to see what the other zap_* tools will talk to, and after zap_start or
zap_stop to confirm what changed. It asks the daemon, not a target, so it puts nothing in the site
tree and collects no alerts. Every zap_* tool auto-starts the daemon, so a stopped daemon here is
not something to fix by hand before a scan.

## Key options

Nothing is required.

- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

The running or stopped status, and the ZAP version. Reconix has no reader for zap_status, so no
findings come from it; the masked output is kept on the tool run for a person to read.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only` and is not destructive, and
`risk_ops.json` has no zap_* entry, so no argument raises a call above `LOW`. Under S4 a `LOW`
action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for one, and an action above
the scope's `max_risk` is blocked. `host` and `port` only choose which daemon to ask, and the
defaults are the ones the rest of the zap_* tools use.
