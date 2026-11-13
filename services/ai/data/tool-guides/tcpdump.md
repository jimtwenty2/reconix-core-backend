# tcpdump

## When to use

Captures packets on a network interface and prints their headers, with a BPF filter to narrow the
capture to one host, port or protocol. Use it to record what crosses an interface during a test.
It always terminates after `count` packets, so it is a bounded look at live traffic, not a long
recording. For full protocol dissection, display filters, or reading a pcap file instead of
capturing live, the neighbouring catalog tool is tshark.

## Key options

- `interface` — the interface to capture on. The documented default is `eth0`, and `any` captures
  on all of them. Nothing in the schema is required, so an omitted `interface` uses that default.
- `count` — the packets to capture before exiting. The documented default is `50`, and the capture
  always terminates there.
- `filt` — a BPF filter, for example `tcp port 80`, `host 10.0.0.1` or `icmp`. Omitted, the capture
  takes whatever the interface sees.
- `timeout` — per-call timeout in seconds. A narrow filter on a quiet interface reaches `count`
  slowly, so raise it there.

## Output

The headers of the packets it captured, as many as `count` asks for. Reconix has no reader for
tcpdump, so no findings are parsed from that text and the masked output is kept on the tool run.

## Risk notes

The catalog baseline is `MEDIUM`, so a call waits for a person and anything above the scope's
`max_risk` is `BLOCKED`. `risk_ops.json` lists no escalation patterns for tcpdump, and it is
neither `destructive` nor one of the free-shell tools. It needs raw-socket privileges, and the
container runs with `NET_RAW`. Two things bound it: the capture always terminates after `count`
packets, and `timeout` ends the call. tcpdump has no `target` property, so the scope's allowed
tools and time window are what authorize a capture.
