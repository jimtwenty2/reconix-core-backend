# job_result

## When to use

Fetches a finished background job's result envelope by `job_id`. Call it once `job_status` reports
the job is `done` or `failed` to read the wrapped tool's output. If the job is still running it
says so — keep waiting through `job_status` — so call `job_result` once the job has finished, read
the findings it returns, then summarize them.

## Key options

- `job_id` (required) — the job id returned by `run_job`.

## Output

The wrapped tool's own result envelope for a `done` or `failed` job, or a note that it is still
running. Reconix has no reader for the job meta tools, so no findings are parsed from job_result
itself; the masked output is kept on the tool run. Read the findings the envelope returns and
summarize them; captured or secret-shaped values are masked by the harness (S8).

## Risk notes

The catalog baseline is `low` and the entry is read-only, so under S4 a job_result call runs
without waiting for a person, and anything above the scope's `max_risk` is `BLOCKED`.
`risk_ops.json` has no entry for it. It reads a finished job's result and nothing else; the scan
that produced it was still bound by the scope and risk rules (S3, S4) at the tool that actually
ran.
