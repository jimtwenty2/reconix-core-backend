# schemathesis

## When to use

Property-based API fuzzer driven by an OpenAPI or GraphQL schema. Point it at a schema and it
generates and sends test cases for every operation, flagging server errors and schema violations.
Use it when you have an API spec and want to fuzz the documented operations for unhandled errors
and contract breaks; to replay a saved request collection as-is use newman, and to review already
captured traffic use mitmproxy.

## Key options

- `schema` (required) — the schema URL (the spec's example points at a host's `openapi.json`) or a
  local schema file.
- `base_url` — the API base URL; required when `schema` is a local file.
- `headers` — request headers, the spec names Authorization or Cookie as examples. Header values
  sent are masked by the harness (S8) before anything is stored or shown.
- `max_examples` — the maximum number of generated examples per operation.
- `opts` — additional `schemathesis run` options, such as `--checks all` or `--include-path /users`.
- `timeout` — per-call timeout in seconds.

## Output

A per-operation pass/fail report. Reconix reads it into one finding per operation and check: a
server error (`ST101`, an unhandled 5xx) becomes a `MEDIUM` finding with the response detail kept
as evidence, and the other codes (undocumented status or content type, schema or method mismatch)
become `LOW` contract findings. schemathesis exits non-zero when it finds issues, and Core lists
it in `FINDINGS_ON_NONZERO_EXIT`, so a run marked FAILED or TIMED_OUT that still left output is
parsed for findings rather than thrown away.

## Risk notes

The catalog baseline is `medium`, so under S4 a call waits for a person to approve it, and
anything above the scope's `max_risk` is `BLOCKED`. `risk_ops.json` has no entry for schemathesis,
so no per-call option raises it above that baseline. The scope check still applies (S3):
schemathesis must be one of the scope's allowed tools, and the schema URL or `base_url` host must
sit inside the approved targets and not be excluded, with any `..` path traversal blocked.
