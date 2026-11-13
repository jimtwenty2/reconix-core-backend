# wfuzz

## When to use

A feature-rich web application brute-forcer. Put the FUZZ keyword in the target URL or in POST
data, and each word from the wordlist is sent in its place. Use it for content discovery and for
parameter and form fuzzing, normally after a fingerprint has shown how the target answers. ffuf is
the faster Go fuzzer for the same content discovery and for vhost enumeration, gobuster
brute-forces directories, DNS subdomains and vhosts, arjun finds the undocumented parameters
first, and sqlmap, commix and dalfox then test one of them for SQL injection, command injection or
XSS.

## Key options

- `target` — required. The target URL with the FUZZ keyword where each word goes, for example
  `http://example.com/FUZZ`.
- `wordlist` — required. The path of a wordlist file. Every word in it becomes a request, so the
  list decides how heavy the run is.
- `filter_code` — the HTTP codes to HIDE from the output, for example `404,500`. Omit it to hide
  nothing.
- `opts` — additional wfuzz options. The spec's own example puts the keyword in POST data, so a
  form field can be fuzzed; write the body with FUZZ where each word goes.
- `timeout` — per-call timeout in seconds. Raise it for a long wordlist against a slow target.

## Output

The spec's own words: responses with status codes and word, line and character counts. Reconix has
no reader for wfuzz, so none of its output is parsed into findings — a tool that is not in the
`READERS` table gives no findings at all. The masked output is still kept on the tool run, so a
person reads the hits there. When the same job should end in findings, ffuf and gobuster are the
content-discovery tools that do have a reader, in `findings/paths.py`.

## Risk notes

The catalog baseline is `MEDIUM`, so under S4 even a plain fuzzing run waits for a person, and a
call above the scope's `max_risk` is BLOCKED with HTTP 422. `risk_ops.json` raises a call to
`HIGH` when its argument values contain `-x post`, `-x put`, `-x delete` or `-x patch` — the write
methods. The match rule is the file's own: the call's argument values are lowercased, joined with
spaces and substring-tested against each pattern, and the call's risk is the higher of the
baseline and the top tier that matched. wfuzz is not marked destructive. Both the target and the
wordlist path must stay inside the approved scope: S3 lets nothing run outside the approved
targets, exclusions, time window, allowed tools and max risk.
