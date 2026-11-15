# run_command

## When to use

Executes an allowlisted command on the Kali system. Use it ONLY as a fallback when the specific
tool you need has no dedicated MCP tool. It runs through `/bin/bash`, so full shell syntax works:
pipes, chaining, redirection and command substitution. When a catalog tool already does the job,
call that tool instead of wrapping it here.

## Key options

- `command` (required) — the shell command to run, for example `whois example.com` or
  `dig example.com ANY`.
- `timeout` — timeout in seconds (default 120, maximum 600).

## Output

The command's stdout and stderr. Reconix has no reader for run_command, so no findings are parsed;
the masked output is kept on the tool run. Anything secret-shaped in that output is masked by the
harness (S8) before it is saved, logged, shown or sent to the AI.

## Risk notes

The catalog baseline is `high`, and run_command is also a free-shell tool (with `proxychains`,
`msfconsole` and `smbclient`), so it is exempt from the shell-metacharacter block and the risk
check keeps it at `HIGH`. Under S4 a `HIGH` call waits for a person and S5 has that person type
the target; above the scope's `max_risk` it is `BLOCKED`. `risk_ops.json` has no entry for it. Its
own safety rule, from the spec, is an allowlist: only known-safe binaries may run, every binary in
a chain, pipeline or substitution must be allowlisted, and system-damaging commands (`rm`, `dd`,
`shutdown`, `mkfs`, `sudo`, and interpreters such as `python3`) are rejected. The scope rules
still apply (S3): run_command must be an allowed tool, and what the command reaches must stay
inside the approved scope.
