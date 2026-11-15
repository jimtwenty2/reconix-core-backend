# hashcat

## When to use

The GPU-accelerated password cracker, with 300+ hash modes. Use it for a hash set that john, which
is CPU-based, would take too long over. Run `hash_identifier` first when the hash type is unclear,
because hashcat REQUIRES the `mode` number matching the hash. `responder` captures the NTLMv2
hashes that hashcat mode 5600 cracks.

## Key options

- `hashfile` — a path to a file of hashes inside the container. Required.
- `wordlist` — a path to a wordlist inside the container. Required. `cewl` builds one from website
  content and `crunch` from a character set.
- `mode` — the hash-type mode number, for example `0`=MD5, `100`=SHA1, `1000`=NTLM, `1400`=SHA256 or
  `1800`=sha512crypt. The schema does not mark it required, but the spec says hashcat REQUIRES the
  `mode` number matching the hash type, so use `hash_identifier` if unsure.
- `opts` — additional hashcat options, for example `-r rules/best64.rule` or `--show`.
- `timeout` — per-call timeout in seconds. CPU-only in this container is slow, so raise it.

## Output

Cracked hash:plaintext pairs and status lines. Reconix keeps no findings from hashcat: `READERS`
in the API's `services/findings.py` has no entry for it, so `parse_run` returns none and only the
masked output stays on the tool run.

## Risk notes

The catalog baseline is `LOW` and hashcat is `read_only`, so a run goes ahead without waiting for
a person, while anything above the scope's `max_risk` is blocked. `risk_ops.json` has no hashcat
entry, so no option — a rule file included — raises a call above that baseline. Hashcat reads a
hash file and a wordlist inside the container. A cracked pair puts a real credential in the
output, and rule S8 masks secrets before anything is saved, logged, shown or sent to the AI, so a
person reads the raw tool run rather than the model.
