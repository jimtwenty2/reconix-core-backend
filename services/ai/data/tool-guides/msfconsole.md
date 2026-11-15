# msfconsole

## When to use

The console that runs a Metasploit module: exploit, auxiliary and post modules, non-interactively,
one command string at a time. Use it LAST in the family — `msf_search` to find a module, `msf_info`
to read its options, then `msfconsole` to run it. Build a payload with `msfvenom` instead, and batch
a whole script with `msf_resource`. The spec's own note is that startup is slow, about 30 seconds,
so the per-call timeout has to cover the start before the module does any work.

## Key options

- `command` — required. The msfconsole command to run, several chained with `;` when a module needs
  more than one. The spec's own example is `use auxiliary/scanner/ssh/ssh_version`, then setting the
  target and running the module.
- `resource_file` — path to a `.rc` resource script. The spec is explicit that it OVERRIDES
  `command` when set, so a call that sends both runs the script and ignores the command.
- `opts` — commands to chain after the main command.
- `timeout` — per-call timeout in seconds. Startup alone is about 30 seconds, so leave room for the
  module after it.

## Output

The command's output, as text. Reconix has no reader for `msfconsole`, so nothing here is parsed
into findings: the masked output is kept on the tool run and a person reads it. Anything a module
prints about a session it opened is masked before it is saved, logged, shown or sent to the AI.

## Risk notes

The catalog baseline is `HIGH`, and two rules would put it there anyway. `msfconsole` is one of the
free-shell tools, so the command check lets shell metacharacters through in its arguments; and the
catalog marks it `destructive`. The risk check raises a free-shell or destructive tool to at least
`HIGH` whatever the baseline says. Under S4 that means every call waits for a person, and a `HIGH`
action needs the person to type the target; anything above the scope's `max_risk` is blocked. It has
no entry in `risk_ops.json`, so no argument value raises a call further — it is already at the top
tier, where a pattern would be a no-op.
