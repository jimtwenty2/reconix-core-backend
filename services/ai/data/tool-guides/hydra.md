# hydra

## When to use

Network login brute-force across 50+ protocols (ssh, ftp, http-*, rdp, smb, mysql). Use it on a
live login service the scope approves, with the service name, one username or a user wordlist, and
a password wordlist. For offline hash cracking use john or hashcat instead: hydra attacks the
service, they work on a file of hashes.

## Key options

- `target` — the target host or IP. Required.
- `service` — the service to attack, for example `ssh`, `ftp`, `http-post-form`, `rdp`, `smb` or
  `mysql`. Required.
- `userlist` — a single username OR a path to a user wordlist. Required.
- `passlist` — a path to a password wordlist. Required. `cewl` builds one from website content and
  `crunch` from a character set.
- `opts` — additional hydra options, for example `-t 4` or `-V`.
- `timeout` — per-call timeout in seconds. A brute force tries many passwords against a live
  service, so raise it.

## Output

Found login/password pairs, or none. Reconix keeps no findings from hydra: `READERS` in the API's
`services/findings.py` has no entry for it, so `parse_run` returns none and only the masked output
stays on the tool run.

## Risk notes

The catalog baseline is `HIGH`, hydra is marked `destructive`, and the harness risk check raises a
destructive tool to HIGH whatever the baseline says, so a hydra call always waits for a person and
is blocked outright when the scope's `max_risk` is below HIGH. `risk_ops.json` has no hydra entry,
so no option raises a call above that. Hydra hammers a live service: account lockout and service
load are the tester's call, and the scope check is what keeps the attack inside the approved
targets. A successful run puts a real credential in the output, and rule S8 masks secrets before
anything is saved, logged, shown or sent to the AI, so a person reads the raw tool run rather than
the model.
