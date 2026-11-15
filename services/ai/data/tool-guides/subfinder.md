# subfinder

## When to use

Passive subdomain discovery from many online sources — certificate transparency, search engines and
DNS datasets — with no direct DNS queries. Use it first on an in-scope apex domain when the run
should not touch the target's own name servers. dnsrecon is the DNS job (records, subdomain brute
force, reverse lookups, zone transfers), amass is more thorough than subfinder but slower and can
add active DNS, and theHarvester harvests emails, hosts, IPs and URLs from public sources.

## Key options

- `domain` — required. The target apex domain, for example `example.com`. The spec is explicit that
  it takes no subdomains here: pass the apex and let subfinder find the rest.
- `opts` — additional subfinder options. The spec's example is `-all`; it documents no default.
- `timeout` — per-call timeout in seconds. The run queries many online sources, so a slow one needs
  more room.

## Output

Discovered subdomains, in the spec's own words; it documents no output format. Reconix has no
reader for subfinder — it is not in the `READERS` table in
`services/api/src/reconix_api/services/findings.py` — so `parse_run` returns no findings and the
masked output stays on the tool run. A discovered subdomain is not in scope just because it was
found: the scope check matches a domain against the scope's domain entries, so a subdomain needs an
exact entry or a `*.domain` wildcard one before another tool may run on it.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and subfinder is
not one of the free-shell tools, so nothing raises a call to HIGH: under S4 a `LOW` call runs now,
`MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked.
`risk_ops.json` has no subfinder entry, so no option escalates a call and the risk check always
allows it. Passive means the target is not queried, not that nothing leaves the container: the
spec's sources are online, so the domain name goes to third parties. The target must be a
plain-form domain (ASCII, punycode for international names, lower case, no trailing dot, no port),
and when the scope lists allowed ports a bare domain target is refused, since Core cannot limit the
ports a non-nmap tool reaches.
