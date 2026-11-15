# mitmproxy

## When to use

Analyzes captured HTTP(S) API traffic from a saved mitmproxy flow file using mitmdump in
non-interactive mode. Point `flow_file` at a saved capture to read back the request/response
transactions for review. This reads existing captures only: the spec puts live interception out of
scope, since that needs mitmdump running as a proxy with a client configured to use it.

## Key options

- `flow_file` (required) — the path to a saved mitmproxy flow file to read (the spec's example is a
  `.flow` capture under `/workspace/`).
- `opts` — additional mitmdump options, such as a `--flow-filter` with the `~u /api` URL filter.
- `timeout` — per-call timeout in seconds.

## Output

The request/response transactions from the capture, for review. Reconix has no reader for
mitmproxy, so no findings are parsed; the masked output is kept on the tool run. A capture can
hold session cookies and other credentials, and the harness masks those captured values (S8)
before anything is saved, logged, shown or sent to the AI.

## Risk notes

The catalog baseline is `low` and the entry is read-only, so under S4 a plain call runs without
waiting for a person, and anything above the scope's `max_risk` is `BLOCKED`. `risk_ops.json` has
no entry for mitmproxy, so no option raises it above that baseline. The scope rules still apply
(S3): mitmproxy must be one of the scope's allowed tools, and the flow file is read from a path —
the spec's example sits under `/workspace/` — with any `..` path traversal blocked.
