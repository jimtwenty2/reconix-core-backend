# msf_info

## When to use

Shows one Metasploit module's details: its description, its options, its targets and its
references. The spec says to use it after `msf_search` — search for candidates there, read the one
you want here, then run it with `msfconsole`. It is the read-only middle step of the family, before
anything runs and before any payload is built with `msfvenom`.

## Key options

- `module_path` — required. The full module path, for example `auxiliary/scanner/smb/smb_version`.
  A search result gives you this path; `msfconsole` needs the same one to `use` the module.
- `timeout` — per-call timeout in seconds.

## Output

The module's info and option table. Reconix has no reader for `msf_info`, so nothing here is
parsed into findings: the masked output is kept on the tool run and a person reads it to see which
options the module wants before `msfconsole` runs it.

## Risk notes

The catalog baseline is `LOW` and the catalog marks it `read_only`. Under S4 a `LOW` action runs
now, `MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked. It
has no entry in `risk_ops.json`, so nothing a module path contains raises a call above that
baseline. Reading a module changes nothing; `msfconsole` is where the risk appears. Its output is
masked under S8 before it is saved, logged, shown or sent to the AI.
