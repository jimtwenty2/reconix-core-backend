# onesixtyone

## When to use

A fast SNMP scanner: it probes a host on UDP 161 and reports the community strings that are valid
there, with the system description each one returns. Use it for initial SNMP discovery on a host.
The spec compares it to snmpwalk, which is not a tool in the Kali catalog, so onesixtyone is the
SNMP scanner a Reconix action can call. For the rest of the host's ports and services the
neighbouring catalog tool is nmap.

## Key options

- `target` — required. A target IP or hostname.
- `community` — the community string to test. The documented default is `public`. It also takes a
  file path holding a list of them.
- `opts` — additional onesixtyone options.
- `timeout` — per-call timeout in seconds. UDP gets no answer from a silent host, so the timeout is
  what ends that call.

## Output

The valid community strings and the system description of a host that answers; a silent host
prints only onesixtyone's own "Scanning N hosts" banner. Reconix reads that text through
`findings/onesixtyone.py`, which makes one `MEDIUM` finding per answering host and community
string: titled "SNMP readable with community" plus the string, described as readable without
authentication with the system description appended, tagged `CWE-200` and `A05:2021`, with the
output line kept as `snmp_community` evidence and a remediation to disable unused SNMP or replace
default community strings and restrict UDP 161 to trusted hosts. Its dedupe key is the host and
the lower-cased community, so the same pair found again is the same finding. A silent host makes
no finding, and output with neither the banner nor a hit line is an unreadable-output error, not a
clean scan.

## Risk notes

The catalog baseline is `MEDIUM`, so a call waits for a person and anything above the scope's
`max_risk` is `BLOCKED`. `risk_ops.json` lists no escalation patterns for onesixtyone, and it is
neither `destructive` nor one of the free-shell tools. The probe is always UDP 161 and the schema
has no port option for it, so `target` alone decides where the call goes and the approved scope's
target list is what keeps it inside the authorized hosts. When the scope lists allowed ports, a
host target is allowed only if 161 is one of them — the only port onesixtyone can reach — and any
other set is `PORTS_OUT_OF_SCOPE`.
