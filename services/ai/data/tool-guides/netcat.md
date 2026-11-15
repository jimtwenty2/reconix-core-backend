# netcat

## When to use

A TCP/UDP connection utility: connect to a service for a banner grab or a port connectivity test,
or listen on a port with `connect` set to false. Every call is bounded by `timeout`. For
structured enumeration the spec sends you to nmap instead; to see the traffic a connection makes,
the neighbouring catalog tools are tcpdump and tshark.

## Key options

- `host` — required. The target host IP or hostname to connect to, or the bind address when
  listening.
- `port` — required. The port number, for example `80` or `4444`.
- `connect` — `true` connects to the host and port, the documented default; `false` listens on the
  port instead.
- `timeout` — per-call timeout in seconds, and also the nc idle timeout, so it is what ends the
  call in both directions.

## Output

The text of the connection: a service's banner on a connect, or the result of the port
connectivity test. Reconix has no reader for netcat, so no findings are parsed from that text and
the masked output is kept on the tool run.

## Risk notes

The catalog baseline is `HIGH`, and netcat is also marked `destructive`, which the harness risk
check raises to at least `HIGH` whatever the baseline says. So every netcat call waits for a
person, and a scope whose `max_risk` is below `HIGH` blocks it as `RISK_ABOVE_SCOPE_MAX`.
`risk_ops.json` lists no escalation patterns for it, and it is not one of the four free-shell
tools. `host` is a bind address rather than a target when `connect` is false, and the scope check
is still what keeps the host inside the approved targets.
