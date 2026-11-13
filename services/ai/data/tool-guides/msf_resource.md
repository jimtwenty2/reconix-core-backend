# msf_resource

## When to use

Executes a Metasploit resource script, a `.rc` file: batch automation of msfconsole commands in one
call. Use it when the same steps repeat, or when a plan is long enough that sending it to
`msfconsole` one command at a time is worse. Same family order as the rest — `msf_search`, then
`msf_info`, then this or `msfconsole` to run what you found, with `msfvenom` building any payload
the script needs.

## Key options

- `script_path` — required. The path to the `.rc` resource script. This is the only argument the
  tool takes, so everything the script does is written in the file, not in the call.
- `timeout` — per-call timeout in seconds. A script is a batch of commands, so raise it above what a
  single call needs.

## Output

The combined output of the script's commands. Reconix has no reader for `msf_resource`, so nothing
here is parsed into findings: the masked output is kept on the tool run and a person reads it. A
session or credential the script dug up is masked before it is saved, logged, shown or sent to the
AI.

## Risk notes

The catalog baseline is `HIGH`, and the catalog also marks it `destructive`, which the risk check
raises to at least `HIGH` on its own. It is not one of the free-shell tools, so the command check
blocks shell metacharacters in its arguments; `msfconsole` is the console in that set. Under S4
every call waits for a person, and a `HIGH` action needs the person to type the target; anything
above the scope's `max_risk` is blocked. The command check reads the script's path, not what is
inside the file, so read the `.rc` before approving it. It has no entry in `risk_ops.json` — at the
top tier a pattern would be a no-op.
