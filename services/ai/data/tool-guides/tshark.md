# tshark

## When to use

Command-line Wireshark: capture live traffic or read a pcap, with full protocol dissection and
display filters. Use it when packet headers alone are not enough — to read a capture that already
exists, or to dissect one protocol properly. It always terminates after `count` packets. For
headers only, straight off an interface, the neighbouring catalog tool is tcpdump.

## Key options

- `iface` — the interface for a live capture. The documented default is `eth0`. Nothing in the
  schema is required.
- `count` — the packets to capture. The documented default is `50`, and the run always terminates
  there.
- `read_file` — read from a pcap file instead of a live capture. Omitted, tshark captures on
  `iface`.
- `filt` — a capture filter, for example `tcp port 80` or `host 10.0.0.1`. Omitted, nothing narrows
  the capture.
- `opts` — additional tshark options or display filters. The spec's example is `-Y http.request`.
- `timeout` — per-call timeout in seconds. A narrow display filter reaches `count` slowly, so raise
  it there.

## Output

The dissected packets, from the live interface or from `read_file` when one is given, up to
`count` of them. Reconix has no reader for tshark, so no findings are parsed from that text and
the masked output is kept on the tool run.

## Risk notes

The catalog baseline is `MEDIUM`, so a call waits for a person and anything above the scope's
`max_risk` is `BLOCKED`. `risk_ops.json` lists no escalation patterns for tshark, and it is
neither `destructive` nor one of the free-shell tools, so no option moves a call off that
baseline. tshark has no `target` property: hosts are named inside `filt` or a display filter in
`opts`, so the scope's allowed tools, targets and time window are what authorize the call. `count`
and `timeout` are what end it.
