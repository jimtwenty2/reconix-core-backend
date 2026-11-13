# msfvenom

## When to use

Generates a Metasploit payload — shellcode or an executable — in a format you choose. Use it after
`msf_search` and `msf_info` have picked a module and before `msfconsole` runs it, when that module
needs a payload of its own. It is also how you list what exists: pass `--list payloads` through
`opts` and the call returns a listing instead of a payload.

## Key options

- `payload` — required. The payload name, for example `linux/x64/shell_reverse_tcp` or
  `windows/meterpreter/reverse_tcp`.
- `lhost` — the callback host the payload connects back to. The spec's own word for it is `LHOST`,
  the callback IP.
- `lport` — the callback port. The spec's own word for it is `LPORT`.
- `fmt` — output format: `raw`, `exe`, `dll`, `python`, `c`, `elf`, `powershell`, and more; the
  spec's list is cut off with an ellipsis.
- `encoder` — an encoder, for example `x86/shikata_ga_nai`.
- `iterations` — encoding iterations. The spec's default is 1.
- `platform` — target platform: `windows`, `linux`, `android`, `osx`.
- `arch` — target arch: `x86`, `x64`, `armle`, `mipsle`.
- `template` — path to a template executable to inject into.
- `outfile` — path the payload is written to.
- `badchars` — bad characters to avoid, for example `\x00\x0a\x0d`.
- `opts` — additional msfvenom options. `--list payloads` here turns the call into a listing.
- `timeout` — per-call timeout in seconds.

## Output

The generated payload, or a listing when you pass `--list payloads` via `opts`. Reconix has no
reader for `msfvenom`, so nothing here is parsed into findings: the masked output is kept on the
tool run and a person reads it. A payload written to `outfile` is a file, not a finding.

## Risk notes

The catalog baseline is `MEDIUM`. `risk_ops.json` raises a single call to `HIGH` when its argument
values contain `reverse_tcp`, `bind_tcp`, `meterpreter`, `shell_reverse`, `/bin/sh`, `/bin/bash`,
`bash -i`, `sh -i`, `cmd.exe` or `powershell -` — every one of those describes a callback shell. Its
`match` rule substring-tests each pattern against the call's argument values, lowercased and joined
with spaces, so the payload name on its own decides it. Under S4 `LOW` runs now, `MEDIUM` and `HIGH`
wait for a person, and anything above the scope's `max_risk` is blocked. The payload, and any
`outfile` or `template` path, stay inside what the scope check allows. A captured session or
credential in the output is masked under S8 before it is saved, logged, shown or sent to the AI.
