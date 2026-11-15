# john

## When to use

John the Ripper — the offline password-hash cracker with format auto-detection. Use it on a file
of hashes you already hold, when a CPU-based crack of a smaller hash set is enough; for GPU
cracking use hashcat. Run `hash_identifier` first when the format is not obvious, since it names
the format to force. Hydra is the tool for a live network login, not for a hash file.

## Key options

- `hashfile` — a path to a file of hashes inside the container. Required.
- `wordlist` — a wordlist for a dictionary attack (optional), also a path inside the container.
  `cewl` builds one from website content and `crunch` from a character set.
- `fmt` — force a hash format, for example `raw-md5`, `sha256crypt` or `nt`. John auto-detects the
  format when `fmt` is omitted.
- `opts` — additional john options, for example `--rules` or `--show`.
- `timeout` — per-call timeout in seconds. A CPU crack of a hash set takes time, so raise it.

## Output

Cracked passwords; run with `--show` in `opts` to display prior results. Reconix keeps no findings
from john: `READERS` in the API's `services/findings.py` has no entry for it, so `parse_run`
returns none and only the masked output stays on the tool run.

## Risk notes

The catalog baseline is `LOW` and john is `read_only`, so a run goes ahead without waiting for a
person, while anything above the scope's `max_risk` is blocked. `risk_ops.json` has no john entry,
so no option raises a call above that baseline. John reads a hash file inside the container and
sends only the catalog's own arguments. A cracked hash puts a real credential in the output, and
rule S8 masks secrets before anything is saved, logged, shown or sent to the AI, so a person reads
the raw tool run rather than the model.
