# nmap

## When to use

The primary network scanner: host discovery, port scanning, service and version detection, and OS
fingerprinting. Use it FIRST on a network host, before nuclei or ZAP look at what is listening. For
a fast sweep of a large range use masscan or rustscan and then nmap on the open ports; for one
banner grab or a connectivity test on a single port use netcat.

## Key options

- `target` — a bare host, IP or CIDR, for example `metasploitable`, `10.0.0.5` or
  `192.168.1.0/24`. Never a URL: no `http://` and no port inside the host.
- `ports` — the ports to scan, such as `22,80,443` or `1-1000`. Omit it for the top 1000 ports.
- `opts` — nmap options. Setting it REPLACES the default `-sV -sC`, so include what you need. Add
  `-Pn` for hosts that drop pings (common for lab VMs), or nmap may report them down.
- `timeout` — per-call timeout in seconds. Wide scans (CIDR ranges, a full `-p-`) can be slow, so
  raise it.

## Output

Returns nmap XML. Reconix reads that XML into one finding per open port on a host, titled from the
port and the detected service, with the port's XML kept as evidence. An open port is a fact, not a
weakness, so its severity is `NONE`; weaknesses on that port come from nuclei and ZAP as their own
findings. XML that does not parse is an unreadable-output error, not a clean scan with nothing in
it.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain service scan runs without waiting for a person,
and anything above the scope's `max_risk` is blocked. `risk_ops.json` raises one call above that
baseline when its argument values contain `--script`, `-su`, `-a `, `-o `, `-t4`, `-t5` or
`--min-rate` (to `MEDIUM`, a person approves it), or an offensive NSE category such as
`--script=exploit`, `--script=vuln`, `--script=dos` or `--script=brute` (to `HIGH`). A wide port
range keeps the `LOW` baseline, so set the scope's `max_risk` and the target list with care: the
scope check is what keeps the scan inside the approved hosts. When the scope lists allowed ports,
nmap has to name them itself: no `-p` is `PORTS_NOT_GIVEN`, a glued `-p22` or `-p-` is `BAD_PORTS`,
and `-p-`, `-F`, `--top-ports`, `-O`, `-A`, `-sC` or `--script` are `PORTS_OUT_OF_SCOPE`, because
they probe ports the scope never named — so the default `-sV -sC` is refused there and `opts` must
drop `-sC`. Such a call also needs `-Pn`, or it is `HOST_DISCOVERY_NOT_ALLOWED`.
