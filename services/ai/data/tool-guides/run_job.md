# run_job

## When to use

Starts another tool as a background job and returns its `job_id` immediately instead of blocking
until the tool finishes. Use it for the slow scans the spec names — `zap_scan`, `zap_active_scan`,
`zap_spider`, `nuclei`, a large nmap (a CIDR range or `-p-`) and big semgrep runs — because a
direct call to those can exceed the client timeout while run_job never does. Then poll
`job_status` and read the result envelope with `job_result`.

## Key options

- `tool` (required) — the name of the tool to run as a job, any tool except the meta job tools.
- `args` — the arguments object passed to that tool, exactly as a direct call would take.

## Output

Returns the `job_id` right away; the wrapped tool's own result comes back later through
`job_result`. Reconix has no reader for the job meta tools, so no findings are parsed from run_job
itself; the masked output is kept on the tool run. Whatever the started tool produces is read from
its result envelope when the job finishes.

## Risk notes

The catalog baseline for run_job is `low`, so under S4 the wrapper call runs without waiting for a
person, and anything above the scope's `max_risk` is `BLOCKED`. `risk_ops.json` has no entry for
it. That low baseline is the wrapper's own: S1 and S2 run the harness check on every action, so
the tool a job starts is still checked at that tool's own risk and against the scope. Wrapping a
slow scan in a job is not a way to lower the risk of what actually runs.
