# masscan

## When to use

An ultra-fast asynchronous TCP port scanner for large IP ranges, and much faster than nmap for
bulk scanning. Use it for the first sweep of a range, before anything looks at what is listening:
it does no service or version detection, and the spec's own follow-up is nmap on the open ports it
found. For a quick port sweep of a single host or a small CIDR the neighbouring catalog tool is
rustscan.

## Key options

- `target` — required. A target IP or CIDR range, for example `10.0.0.0/8` or `192.168.1.0/24`.
- `ports` — the ports to scan, such as `80,443,22`. The documented default is `1-65535`, so
  omitting it scans every port.
- `rate` — packets per second. The documented default is `1000`; a higher rate sends a wide range
  faster.
- `timeout` — per-call timeout in seconds. A full `1-65535` sweep of a large CIDR is the slow case,
  so raise it there.

## Output

The open TCP ports it found on the range, with no service or version detection attached — that is
what the nmap follow-up adds. Reconix has no reader for masscan, so no findings are parsed from
its output and the masked output is kept on the tool run.

## Risk notes

The catalog baseline is `MEDIUM`, so a masscan call waits for a person, and a call above the
scope's `max_risk` is `BLOCKED`. `risk_ops.json` lists no escalation patterns for masscan, so no
argument value raises one call above that baseline, and it is neither `destructive` nor one of the
free-shell tools. It needs raw-socket privileges, and the container runs with `NET_RAW`. A wide
CIDR keeps the same baseline, so the scope check on targets is what keeps the sweep inside the
approved hosts. When the scope lists allowed ports, a host, IP or CIDR target is refused as
`PORTS_NOT_SUPPORTED`: masscan picks its own ports and Core cannot limit them, so it only runs on a
scope with no port list.
