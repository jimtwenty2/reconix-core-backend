# gobuster

## When to use

A fast multi-mode brute-force tool, written in Go, for discovering hidden paths and subdomains:
`dir` for directories and files, `dns` for subdomains, `vhost` for virtual hosts. Use it on a web
target after a fingerprint has shown the service answers, when the question is what else is
reachable. It reports a list, so it feeds the next step rather than concluding anything: ffuf and
wfuzz do content discovery with a status-code filter or with the FUZZ keyword in a parameter or
header, arjun looks for undocumented parameters on a path it found, and sqlmap, commix and dalfox
then test one of those parameters for SQL injection, command injection and XSS.

## Key options

- `target` — required. A target URL for `dir` and `vhost`, including `http://` or `https://`, or a
  domain for `dns`.
- `wordlist` — required. The path of a wordlist file; the spec's example is
  `/usr/share/wfuzz/wordlist/general/common.txt`. Every word in it is tried against the target, so
  the list decides how heavy the run is.
- `mode` — `dir` (the default), `dns` or `vhost`.
- `opts` — additional gobuster options; the spec's example is `-x php,html,txt`.
- `timeout` — per-call timeout in seconds. A long wordlist against a slow target takes a while, so
  raise it.

## Output

The spec's own words: discovered paths and subdomains with HTTP status codes. Reconix reads the
quiet form of that output — a path with its `Status` and `Size` on one line — with
`findings/paths.py`. Paths are grouped, not one finding per path: one `NONE` summary finding per
run counts them and keeps the paths as evidence, capped at 100 (`MAX_EVIDENCE`), and then one
finding per kind of sensitive path name. A bare word is normalised to a path first, so the
sensitive-name check sees it. Severity comes from the name alone and is never guessed higher: a
path that would leak a secret, a key, source or data is HIGH, an admin, configuration, backup,
history, debug or exposed file store is MEDIUM, and anything a name only hints at stays LOW.

## Risk notes

The catalog baseline is `MEDIUM`, so under S4 even a plain directory brute-force waits for a
person, and a call above the scope's `max_risk` is BLOCKED with HTTP 422. `risk_ops.json` raises a
call to `HIGH` when its argument values contain `-m post`, `-m put`, `-m delete` or `-m patch` —
the write methods. The match rule is the file's own: the call's argument values are lowercased,
joined with spaces and substring-tested against each pattern, and the call's risk is the higher of
the baseline and the top tier that matched. gobuster is not marked destructive. Both the target
and the wordlist path must stay inside the approved scope: S3 lets nothing run outside the
approved targets, exclusions, time window, allowed tools and max risk.
