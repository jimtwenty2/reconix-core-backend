# zap_start

## When to use

Starts, or verifies, the headless OWASP ZAP daemon that every other zap_* tool talks to. Normally
you do not need to call this — every zap_* tool auto-starts the daemon — so it is worth a call
only when you want the daemon up and checked before a long ZAP sequence, or when it must listen
somewhere other than the defaults. Java 17/21 is selected automatically, because ZAP 2.17 is
unstable on Java 25. It starts the daemon only: it sends nothing to a target and finds nothing to
report.

## Key options

Nothing is required.

- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

The ZAP version and address, once the daemon is ready. Reconix has no reader for zap_start, so no
findings come from it; the masked output is kept on the tool run, and zap_status is what reports
whether that same daemon is running and reachable.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only` and is not destructive, so the
harness does not raise it, and `risk_ops.json` holds no zap_* pattern that would escalate a single
call. Under S4 a `LOW` action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for
one, and an action above the scope's `max_risk` is blocked. The daemon stays up and holds
resources until zap_stop shuts it down.
