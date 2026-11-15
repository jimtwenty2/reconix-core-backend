# job_status

## When to use

Checks a background job's state by `job_id`: `running`, `done` or `failed`. Use it to poll a job
that `run_job` started. Poll it a few seconds apart, not in a tight loop, and stop as soon as the
state is no longer `running`; then call `job_result` once to read the output.

## Key options

- `job_id` (required) — the job id returned by `run_job`.

## Output

The job's state string — `running`, `done` or `failed`. Reconix has no reader for the job meta
tools, so no findings are parsed from job_status; the masked output is kept on the tool run. It
reports state only, so the actual tool result still comes from `job_result`.

## Risk notes

The catalog baseline is `low` and the entry is read-only, so under S4 a job_status call runs
without waiting for a person, and anything above the scope's `max_risk` is `BLOCKED`.
`risk_ops.json` has no entry for it. It reads a job's state and nothing else; the scan the job
runs is still bound by the scope and risk rules (S3, S4) at the tool that actually runs.
