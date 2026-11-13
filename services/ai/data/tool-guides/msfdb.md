# msfdb

## When to use

Manages the Metasploit PostgreSQL database: `init`, `start`, `stop`, `status`, `reinit` and
`delete`. The spec says to run `init` once before first use. It is the setup step of the family —
the other five search the module database, read one module, run it or build a payload, and this is
the one that manages the database itself. Use `status`, which the spec makes the default, to check
the state before you go further.

## Key options

- `command` — the DB command: `init`, `start`, `stop`, `status` (default), `reinit` or `delete`.
  The schema requires nothing, so a call with no `command` is a `status`.
- `opts` — additional msfdb options.
- `timeout` — per-call timeout in seconds.

## Output

Database state messages. Reconix has no reader for `msfdb`, so nothing here is parsed into
findings: the masked output is kept on the tool run and a person reads it to see whether the
database came up, was already running, or is gone.

## Risk notes

The catalog baseline is `LOW` and the catalog marks it `read_only`. Under S4 a `LOW` action runs
now, `MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked.
It has no entry in `risk_ops.json`, so no argument value raises a call above that baseline —
including `delete` and `reinit`, which the catalog does not mark `destructive`. Its output is
masked under S8 like every tool's before it is saved, logged, shown or sent to the AI.
