# crunch

## When to use

Generates a wordlist from a length range, a character set and/or a pattern. Use it when the
password you expect has a known shape or known characters, and feed the list to john or hashcat
for an offline crack, or to hydra against a network login. For wordlists built from website
content use cewl.

## Key options

- `min_len` — the minimum word length. Required.
- `max_len` — the maximum word length. Required: crunch needs the length range, so both ends are
  required and neither has a default in the spec.
- `charset` — the character set, for example `0123456789` or `abc123!@#`.
- `output` — an output file path to save the wordlist to.
- `opts` — additional crunch options, for example `-t @@@%%%` for a pattern.
- `timeout` — per-call timeout in seconds.

## Output

The wordlist on stdout, or to `output` when that path is given. Reconix keeps no findings from
crunch: `READERS` in the API's `services/findings.py` has no entry for it, so `parse_run` returns
none and only the masked output stays on the tool run.

## Risk notes

The catalog baseline is `LOW` and crunch is `read_only`, so a run goes ahead without waiting for a
person, while anything above the scope's `max_risk` is blocked. `risk_ops.json` has no crunch
entry, so no option raises a call above that baseline. A generated word is a candidate, not a
credential, but the crack that uses the list puts a real credential in the cracking tool's output,
and rule S8 masks secrets before anything is saved, logged, shown or sent to the AI, so a person
reads the raw tool run rather than the model.
