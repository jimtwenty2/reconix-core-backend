# amass

## When to use

Attack-surface mapping through OSINT and, optionally, active DNS: it discovers subdomains, IPs,
ASNs and related domains. Use it on an in-scope domain when one subdomain list is not enough and
you want the wider picture, and accept the spec's trade-off — more thorough than subfinder, but
slower. subfinder is the faster passive list, dnsrecon does the DNS records, brute force, reverse
lookups and zone transfers, and theHarvester harvests emails, hosts, IPs and URLs from public
sources.

## Key options

- `domain` — required. The target domain, for example `example.com`.
- `mode` — `enum` (subdomains) is the documented default, `intel` is OSINT on IP ranges and ASNs.
  Omit it for `enum`.
- `opts` — additional amass options. The spec's example is `-active`, which is how the "optionally
  active DNS" in its description is turned on.
- `timeout` — per-call timeout in seconds. The spec calls amass slower than subfinder, so a full
  `enum` needs a longer one.

## Output

The spec documents no output format, only what amass discovers: subdomains, IPs, ASNs and related
domains. Reconix has no reader for it — `amass` is not in the `READERS` table in
`services/api/src/reconix_api/services/findings.py` — so `parse_run` returns no findings and the
masked output stays on the tool run. What it names still has to pass the scope check on its own: a
subdomain needs an exact domain entry or a `*.domain` wildcard one, and an IP amass reports is only
a valid target if the scope's IP ranges cover it.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and amass is not
one of the free-shell tools, so nothing pushes a call to HIGH: under S4 a `LOW` call runs now,
`MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked.
`risk_ops.json` has no amass entry, so `-active` in `opts` does not raise the call — active DNS
still runs at `LOW` with no person asked, and a `LOW` call with no escalation is always allowed by
the risk check. The scope check is the only bound: the target must be a plain-form domain (ASCII,
punycode for international names, lower case, no trailing dot, no port), and when the scope lists
allowed ports a bare domain target is refused, since Core cannot limit the ports a non-nmap tool
reaches.
