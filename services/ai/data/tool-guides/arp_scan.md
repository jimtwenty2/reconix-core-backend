# arp_scan

## When to use

ARP-based host discovery on a local network segment: it lists the live hosts by IP, MAC and
vendor. Use it at the start of a LAN test to find which hosts are there, then nmap on those hosts
for ports, services and versions. It needs a LAN interface and raw sockets to be useful, so it is
for a local segment rather than a routed range.

## Key options

- `target` — required. An IP range or CIDR, for example `192.168.1.0/24`, or `--localnet`.
- `iface` — the interface to use. Auto-detected when it is omitted.
- `opts` — additional arp-scan options.
- `timeout` — per-call timeout in seconds. A whole `/24` is the slow case, so raise it there.

## Output

The live hosts on the segment, each with its IP, its MAC address and its vendor. Reconix has no
reader for arp_scan, so no findings are parsed from that list and the masked output is kept on the
tool run.

## Risk notes

The catalog baseline is `MEDIUM`, so a call waits for a person and anything above the scope's
`max_risk` is `BLOCKED`. `risk_ops.json` lists no escalation patterns for arp_scan, and it is
neither `destructive` nor one of the free-shell tools. It needs a LAN interface and raw sockets to
be useful. `--localnet` stands for the local network rather than a range you wrote, so the scope's
approved target list is what keeps the discovery inside the authorized hosts.
