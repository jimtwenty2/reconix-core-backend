# ffuf

## When to use

An extremely fast web fuzzer, written in Go. Put the FUZZ keyword in the target URL — in the path,
a parameter or a header — and each word from the wordlist is sent in its place. Use it for content
discovery, parameter fuzzing and vhost enumeration, normally after a fingerprint has shown how the
target answers. gobuster brute-forces directories, DNS subdomains and vhosts, wfuzz is the
feature-rich alternative for content and form fuzzing, and arjun finds the undocumented parameters
worth fuzzing before sqlmap, commix or dalfox test one for SQL injection, command injection or XSS.

## Key options

- `target` — required. The target URL with the FUZZ keyword where each word goes, for example
  `http://example.com/FUZZ`.
- `wordlist` — required. The path of a wordlist file. Every word in it becomes a request, so the
  list decides how heavy the run is.
- `match_code` — the HTTP status codes to match, comma-separated. Omit it for ffuf's own default.
- `opts` — additional ffuf options; the spec's example puts the keyword in a header,
  `-H "Host: FUZZ.example.com"`.
- `timeout` — per-call timeout in seconds. Raise it for a long wordlist against a slow target.

## Output

The spec's own words: matching responses with status, size and words. Reconix reads ffuf's default
output — the found word with its `Status` and `Size` on one line — with `findings/paths.py`. Paths
are grouped, not one finding per path: one `NONE` summary finding per run counts them and keeps
the paths as evidence, capped at 100 (`MAX_EVIDENCE`), and then one finding per kind of sensitive
path name. A bare word is normalised to a path first, so the sensitive-name check sees it. Severity
comes from the name alone and is never guessed higher: a path that would leak a secret, a key,
source or data is HIGH, an admin, configuration, backup, history, debug or exposed file store is
MEDIUM, and anything a name only hints at stays LOW.

## Risk notes

The catalog baseline is `MEDIUM`, so under S4 even a plain fuzzing run waits for a person, and a
call above the scope's `max_risk` is BLOCKED with HTTP 422. `risk_ops.json` raises a call to `HIGH`
when its argument values contain `-x post`, `-x put`, `-x delete` or `-x patch` — the write
methods. The match rule is the file's own: the call's argument values are lowercased, joined with
spaces and substring-tested against each pattern, and the call's risk is the higher of the baseline
and the top tier that matched. ffuf is not marked destructive. Both the target and the wordlist
path must stay inside the approved scope: S3 lets nothing run outside the approved targets,
exclusions, time window, allowed tools and max risk.
