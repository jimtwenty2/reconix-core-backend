# rustscan

## When to use

Very fast open-TCP-port discovery with greppable output. Use it for a quick port sweep before a
deeper nmap service scan, which the spec names as the follow-up: RustScan says which ports are
open, not what is running on them. For a bulk sweep of a large IP range the neighbouring catalog
tool is masscan.

## Key options

- `target` — required. A bare host, IP or CIDR. Not a URL: no scheme and no port inside it.
- `ports` — the ports or a range, such as `80,443` or `1-1024`. Omit it to scan all ports.
- `opts` — additional RustScan options. The spec's own example is `--range 1-1000`.
- `timeout` — per-call timeout in seconds. Omitting `ports` means every port, so allow for that.

## Output

Text, one line per host with its open ports ("host -> open ports"), in the spec's own words.
Reconix has no reader for rustscan, so no findings are parsed from that text and the masked output
is kept on the tool run.

## Risk notes

The catalog baseline is `MEDIUM`, so a call waits for a person and anything above the scope's
`max_risk` is `BLOCKED`. `risk_ops.json` lists no escalation patterns for rustscan, and it is
neither `destructive` nor one of the free-shell tools, so no argument value moves a call off that
baseline. The spec says the call requires an authorized target, and that the target is a bare
host, IP or CIDR rather than a URL: the scope check is what keeps it inside the approved targets.
When the scope lists allowed ports, that host target is refused as `PORTS_NOT_SUPPORTED`, because
RustScan reaches ports the scope never named and Core cannot limit them; it runs on a scope with no
port list.
