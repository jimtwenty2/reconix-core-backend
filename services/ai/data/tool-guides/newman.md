# newman

## When to use

Runs a Postman collection with Newman, the Postman CLI runner. Use it to replay a saved API
request collection against a target and get the per-request assertions and failures back. Reach
for it when the requests already exist as a collection; to fuzz an API from its schema instead use
schemathesis.

## Key options

- `collection` (required) — the path to a Postman collection JSON file.
- `environment` — an optional Postman environment JSON file.
- `opts` — additional `newman run` options, such as `--insecure` or `--timeout-request 5000`.
- `timeout` — per-call timeout in seconds.

## Output

The per-request run report with assertions and failures. Reconix has no reader for newman, so no
findings are parsed from it; the masked output is kept on the tool run. A collection and its
traffic can carry credentials, and the harness masks captured values (S8) before anything is
saved, logged, shown or sent to the AI.

## Risk notes

The catalog baseline is `medium`, so under S4 a call waits for a person to approve it, and
anything above the scope's `max_risk` is `BLOCKED`. `risk_ops.json` has no entry for newman, so no
option raises it above that baseline. The scope rules still apply (S3): newman must be one of the
scope's allowed tools, and the requests it replays must stay inside the approved targets — a
collection pointed outside the approved scope is out of bounds.
