# proxychains

## When to use

Forces another TCP tool's connections through a proxy chain (Tor/SOCKS/HTTP) taken from
`/etc/proxychains4.conf`. Wrap a command such as `nmap -sT target` to route it through the chain.
Use it when a scan must egress through a proxy; it wraps the tool, so the underlying tool's own
use still applies.

## Key options

- `command` (required) — the full command to run through proxychains, the spec's example is
`command` (required) — the full command to run through proxychains, the spec's example is   `nmap
  -sT target.com`.
- `opts` — additional proxychains options, such as `-f custom.conf`.
- `timeout` — per-call timeout in seconds.

## Output

The wrapped tool's output plus proxy debug lines. Reconix has no reader for proxychains, so no
findings are parsed from the wrapper itself; the masked output is kept on the tool run. Any
captured or returned values are masked by the harness (S8) before anything is saved, logged or
shown.

## Risk notes

The catalog baseline is `medium`, but proxychains is one of the free-shell tools (with
`run_command`, `msfconsole` and `smbclient`), so it is exempt from the shell-metacharacter block
and the risk check pins it to `HIGH` whatever the baseline says. Under S4 a `HIGH` call waits for
a person, and S5 has that person type the target; above the scope's `max_risk` it is `BLOCKED`.
`risk_ops.json` has no entry for proxychains. The proxy chain comes from `/etc/proxychains4.conf`
(or the file `-f` names), and the scope rules still apply (S3): proxychains must be an allowed
tool, and what the wrapped command reaches must stay inside the approved targets and not be
excluded.
