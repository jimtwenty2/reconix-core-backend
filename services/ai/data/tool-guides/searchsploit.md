# searchsploit

## When to use

Searches the Exploit-DB for public exploits by software name, version, CVE or keyword. Use it
after a fingerprinting step has named a version — nmap does service and version detection — to
find out whether a public exploit exists for what you just found. It is a lookup, not a scan: it
does not test the target, so it belongs in the analysis between a version and the next proposed
action.

## Key options

- `query` — required. The search term: a CVE such as `CVE-2017-0144`, or a software name and
  version such as `vsftpd 2.3.4`.
- `opts` — additional options. The spec's example, `-m 12345`, copies an exploit rather than
  searching for one. The spec names no default that setting `opts` replaces, unlike nuclei's.
- `timeout` — per-call timeout in seconds. The spec names no default; raise it if a search needs
  longer.

## Output

Matching exploit titles and paths. Reconix has no reader for searchsploit — it is not in the
`READERS` table in `services/findings.py` — so nothing is parsed into finding rows and Reconix
assigns no severity to a match. The masked output is still kept on the tool run, and that is where
the titles and paths are read. What comes back is a list of references for the analyst, not
findings about the target, so a run that saved no findings says nothing about the target either
way.

## Risk notes

The catalog baseline is `LOW` and the tool is marked `read_only`, so a searchsploit call runs now,
with no person waiting to approve it, and `LOW` is the bottom of the harness's risk order, so a
plain search cannot be above the scope's `max_risk`. `risk_ops.json` lists no escalation for it, so
no option value raises a call above `LOW` — not even `-m`, whose own example copies an exploit
instead of searching. The scope check still applies: the call must sit inside the approved targets,
exclusions, time window and allowed tools, and only tools in the Kali catalog may run at all.
