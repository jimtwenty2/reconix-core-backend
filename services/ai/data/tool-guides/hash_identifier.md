# hash_identifier

## When to use

Identifies a hash's likely algorithm(s) with hashID. Run it BEFORE cracking, to pick the right
hashcat mode or john format: hashcat REQUIRES its `mode` number, and john auto-detects a format
only when `fmt` is left out. It names algorithms and cracks nothing, so it costs little before a
long john or hashcat run.

## Key options

- `hash_str` — a hash string to identify, passed as text rather than a file. The schema marks no
  property required, so give either `hash_str` or `hashfile`.
- `hashfile` — a file of hashes to identify, one per line.
- `timeout` — per-call timeout in seconds.

## Output

Ranked candidate hash types. Take the ranking to hashcat as its `mode` or to john as its `fmt`.
Reconix keeps no findings from hash_identifier: `READERS` in the API's `services/findings.py` has
no entry for it, so `parse_run` returns none and only the masked output stays on the tool run.

## Risk notes

The catalog baseline is `LOW` and hash_identifier is `read_only`, so a run goes ahead without
waiting for a person, while anything above the scope's `max_risk` is blocked. `risk_ops.json` has
no entry for it, so no option raises a call above that baseline. Nothing is cracked and no service
is touched, but the input is a hash, which is a credential in another shape: rule S8 masks secrets
before anything is saved, logged, shown or sent to the AI, so a person reads the raw tool run
rather than the model.
