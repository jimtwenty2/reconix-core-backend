# msf_search

## When to use

Searches the Metasploit module database by keyword, CVE, platform or type, without opening an
interactive console. It is the FIRST step of the family: search here, read one match with
`msf_info`, then run it with `msfconsole`. Prefer it to `msfconsole` for looking something up — the
console's own spec notes a slow startup of about 30 seconds, and a search does not pay it.

## Key options

- `query` — required. The search keyword, for example `smb`, `eternalblue`, or a CVE such as
  `CVE-2021-34527`.
- `module_type` — filter by type: `auxiliary`, `exploit`, `post`, `payload`, `encoder` or `nop`.
- `timeout` — per-call timeout in seconds.

## Output

Matching module paths with rank and date. Reconix has no reader for `msf_search`, so nothing here is
parsed into findings: the masked output is kept on the tool run and a person reads it to choose
which module path to hand to `msf_info` next.

## Risk notes

The catalog baseline is `LOW` and the catalog marks it `read_only`. Under S4 a `LOW` action runs
now, `MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked. It
has no entry in `risk_ops.json`, so no query raises a call above that baseline. Its schema names no
target — only a query, a type filter and a timeout — so the scope check has the tool and the time
window to allow. Its output is masked under S8 before it is saved, logged, shown or sent to the AI.
