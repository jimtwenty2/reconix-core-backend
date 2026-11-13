# commix

## When to use

Automated OS command injection detection and exploitation. Use it when a parameter may pass input
to a shell, normally after a crawl or a fingerprint has shown which parameters the endpoint takes.
It handles detection and exploitation, including a pseudo-terminal shell. For SQL injection use
sqlmap; for XSS use dalfox.

## Key options

- `url` — required. The target URL with its parameters, the one holding the parameter that may
  reach a shell.
- `opts` — additional commix options. `--batch` is always applied, so a non-interactive run never
  waits at a prompt.
- `timeout` — per-call timeout in seconds. Exploitation, up to a pseudo-terminal shell, runs longer
  than detection alone, so raise it.

## Output

The spec's own words: it confirms injectable parameters and command execution. Reconix has no
reader for commix, so none of its output is parsed into findings — a tool that is not in the
`READERS` table gives no findings at all. The masked output is still kept on the tool run, so what
commix printed is read there instead of through a finding.

## Risk notes

The catalog baseline is `HIGH` and commix is marked `destructive`; the harness risk check pushes a
destructive tool to at least HIGH whatever the baseline says, so it is HIGH either way. Under S4
every commix call waits for a person, and a call above the scope's `max_risk` is BLOCKED with HTTP
422. `risk_ops.json` defines no patterns for commix: an already-high tool is gated at its baseline,
so a pattern on it could not raise it further. The spec's own wording is detection and
exploitation, including a pseudo-terminal shell, which is why it is destructive: commands run on
the target. commix is not a free-shell tool, so S6 still blocks control and shell characters in its
arguments, and `opts` carries commix options only. The target URL must be inside the approved
scope: S3 lets nothing run outside the approved targets, exclusions, time window, allowed tools and
max risk.
