# dnsrecon

## When to use

DNS enumeration on one domain: records, subdomain brute force, reverse lookups and zone-transfer
attempts. Use it in the recon step when you want the DNS answers themselves rather than a list
collected from public sources. The spec says prefer subfinder for passive subdomain discovery;
amass maps a wider attack surface (subdomains, IPs, ASNs and related domains) and theHarvester
harvests emails, hosts, IPs and URLs from public sources.

## Key options

- `domain` — required. The target domain, for example `example.com`. A bare domain: no scheme, no
  port and no path.
- `opts` — enumeration options. The spec documents `-t std` as the default and `-t axfr` for a
  zone-transfer attempt, so name the enumeration type you want here.
- `timeout` — per-call timeout in seconds. A brute-force or zone-transfer run can be slow, so
  raise it.

## Output

The spec names no output format for dnsrecon. Reconix has no reader for it: `dnsrecon` is not in
the `READERS` table in `services/api/src/reconix_api/services/findings.py`, so `parse_run` returns
no findings and the run's masked output stays on the tool run. Records, subdomains and any
zone-transfer answer are therefore text on that run, not findings with a severity, and each host
they name still has to pass its own scope check before another tool touches it.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and dnsrecon is
not one of the free-shell tools (run_command, proxychains, msfconsole, smbclient), so nothing
pushes a call to HIGH: under S4 a `LOW` call runs now, `MEDIUM` and `HIGH` wait for a person, and
anything above the scope's `max_risk` is blocked. `risk_ops.json` has no dnsrecon entry, so no
option raises a call above that baseline — `-t axfr`, a zone-transfer attempt, is still `LOW` and
no person is asked, and a `LOW` call with no escalation is always allowed by the risk check. The
scope check is what bounds the run: the target must already be in plain form (ASCII, punycode for
international names, lower case, no trailing dot, no port) because the harness blocks rather than
cleans it, and when the scope lists allowed ports a bare domain target is refused, since Core
cannot limit the ports a non-nmap tool reaches.
