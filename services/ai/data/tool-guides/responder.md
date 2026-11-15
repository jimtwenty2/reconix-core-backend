# responder

## When to use

An LLMNR/NBT-NS/mDNS poisoner: it answers name-resolution requests on the local network and
captures the NTLMv2 hashes that come back. It needs a LAN interface and raw sockets, and the run
is bounded by `timeout`. hashcat (mode 5600) is the catalog tool for cracking what it captures,
and nmap is the tool for one host's open ports rather than for the LAN's name resolution.

## Key options

- `interface` — required. The interface to listen on, for example `eth0`; it must be on the target
  network.
- `opts` — additional responder options, for example `-A` analyze mode or `-w` WPAD.
- `timeout` — per-call timeout in seconds; the run is bounded by it.

## Output

Returns the captured hashes. Reconix has no reader for responder, so none of them become findings;
the masked output stays on the tool run, and cracking them is a separate hashcat call.

## Risk notes

The catalog baseline is `HIGH` and responder is marked destructive, which the risk check pushes to
at least `HIGH` too. Under S4 every call waits for a person, and one above the scope's `max_risk`
is blocked. `risk_ops.json` has no responder entry. responder is not a free-shell tool, so the
command check blocks a control character or a shell metacharacter in `interface` or `opts`. A
captured NTLMv2 hash is a credential, so S8 is the rule that covers this output: the harness masks
secrets before anything is saved, logged, shown, sent to the model or stored in Qdrant, and with
no reader the masked output on the tool run is the only copy Reconix keeps.
