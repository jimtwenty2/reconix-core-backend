# theHarvester

## When to use

OSINT harvesting of emails, hosts, IPs and URLs from public sources — search engines, PGP key
servers, Shodan and more. The spec calls it an early-recon tool, so run it on an in-scope domain at
the start of the flow, before anything active, to get the people and hosts behind the target.
subfinder and amass give the subdomain and attack-surface picture instead, and dnsrecon gives the
DNS records.

## Key options

- `domain` — required. The target domain, for example `example.com`.
- `source` — the data source to query. The documented default is `all`, meaning every source; the
  spec's examples of a single one are `google`, `bing` and `crtsh`.
- `limit` — max results per source, an integer. The documented default is 100. Lower it for a quick
  pass, raise it for a wider harvest.
- `opts` — additional theHarvester options. The spec documents no default and no example for it.
- `timeout` — per-call timeout in seconds. With `source` left at `all` the run queries many public
  sources, so give it room.

## Output

The spec names what comes back — emails, hosts, IPs and URLs — and no output format. Reconix has no
reader for it: the catalog name is not in the `READERS` table in
`services/api/src/reconix_api/services/findings.py`, so `parse_run` returns no findings and the
masked output stays on the tool run. Masking runs over that output before it is saved, logged,
shown, sent to the AI or stored in Qdrant, so anything credential-shaped in a harvest becomes a
masked label. The catalog spells the tool `theHarvester`; the harness lowercases tool names when it
looks one up, so the capital H does not have to be reproduced exactly in a call.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and theHarvester
is not one of the free-shell tools, so nothing pushes a call to HIGH: under S4 a `LOW` call runs
now, `MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked.
`risk_ops.json` has no entry for it, so no source, limit or option escalates a call, and a `LOW`
call with no escalation is always allowed by the risk check. It sends nothing to the target itself:
the spec's sources are public third parties, so the domain name is what leaves the container. The
target must be a plain-form domain (ASCII, punycode for international names, lower case, no
trailing dot, no port), and when the scope lists allowed ports a bare domain target is refused,
since Core cannot limit the ports a non-nmap tool reaches.
