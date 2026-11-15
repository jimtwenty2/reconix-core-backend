# arjun

## When to use

Discover the hidden HTTP parameters an endpoint accepts. Use it after a crawl or a fingerprint has
given the endpoint, and before anything is fuzzed: the spec's own description says to find the
undocumented query and body parameters an endpoint accepts before fuzzing them. katana supplies
the URLs to run it on, ffuf and wfuzz then fuzz a parameter it found, gobuster brute-forces paths
and subdomains instead of parameters, and sqlmap, commix and dalfox test one of them for SQL
injection, command injection or XSS.

## Key options

- `url` — required. An absolute HTTP(S) target URL.
- `method` — the request method: GET (the default), POST, JSON or XML.
- `headers` — HTTP headers, for example Authorization or Cookie. A credential sent this way is
  masked before anything is saved, logged, shown or sent to the AI (S8).
- `wordlist` — optional. The path of a parameter wordlist file.
- `delay` — the delay between requests in seconds; the documented default is 0.
- `opts` — additional Arjun options; quoted values are supported.
- `timeout` — the total execution timeout in seconds; the documented default is 300. Probing a
  large parameter set request by request can need more.

## Output

The spec's own words: the list of discovered parameter names. Reconix reads that text with
`findings/arjun.py`: the scanned URL comes from arjun's `Scanning` line and the names from its
`Parameters found` summary, with the per-parameter `parameter detected` lines as a fallback when
there is no summary. One run gives one finding, `NONE`, titled for the host, listing the
parameters and how each was found. The parameters are a fact, not a weakness, so the severity
stays `NONE`; the finding is a lead, and those undocumented inputs are where injection,
access-control and logic flaws are then tested. A run that finds nothing makes no finding, and
text that is not arjun's is an unreadable-output error rather than a clean run.

## Risk notes

The catalog baseline is `MEDIUM`, so under S4 a parameter discovery run waits for a person, and a
call above the scope's `max_risk` is BLOCKED with HTTP 422. `risk_ops.json` raises a call to
`HIGH` when its argument values contain `-m post`, `-m put`, `-m delete` or `-m patch` — the write
methods. The match rule is the file's own: the call's argument values are lowercased, joined with
spaces and substring-tested against each pattern, and the call's risk is the higher of the
baseline and the top tier that matched. arjun is not marked destructive. Both the target and any
wordlist path must stay inside the approved scope: S3 lets nothing run outside the approved
targets, exclusions, time window, allowed tools and max risk.
