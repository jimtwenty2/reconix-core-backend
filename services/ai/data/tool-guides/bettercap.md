# bettercap

## When to use

A MITM framework driven by caplets: ARP and DNS spoofing, sniffing and session hijacking on the
local network. It needs a LAN interface and raw sockets, and the run is bounded by `timeout`. Use
nmap when the job is one host's ports and services, and responder when the job is poisoning name
resolution on the LAN to capture NTLMv2 hashes.

## Key options

- `iface` — the interface to use, for example `eth0`.
- `caplet` — the caplet file of a predefined workflow, for example `http-ui`.
- `opts` — additional bettercap options, for example `-eval "net.probe on"`.
- `timeout` — per-call timeout in seconds; the run is bounded by it.

Nothing in the schema is required. The arguments name an interface and a workflow, not a target
host.

## Output

Returns bettercap's log. Reconix has no reader for bettercap, so no findings are parsed from it;
the masked output stays on the tool run, which is where a spoofing or sniffing session leaves what
it saw, instead of in findings.

## Risk notes

The catalog baseline is `HIGH` and bettercap is marked destructive, which the risk check pushes to
at least `HIGH` as well. Under S4 every call waits for a person, and one above the scope's
`max_risk` is blocked. `risk_ops.json` has no bettercap entry, so no option raises a call further.
bettercap is not a free-shell tool, so the command check blocks a control character or a shell
metacharacter in `iface`, `caplet` or `opts`. Traffic sniffed on the LAN can carry other hosts'
credentials, and S8 treats them as secrets: the harness masks them before anything is saved,
logged, shown, sent to the model or stored in Qdrant.
