# enum4linux

## When to use

Enumerates a Windows or Samba host over SMB (139/445): users, shares, groups, password policy and
OS info, and it needs no credentials. Run nmap first to find the SMB ports on the host, then this,
then smbclient to work with one of the shares it listed. Pass `-a` through `opts` for full
enumeration.

## Key options

- `target` — required. The IP or hostname of the Windows/Samba server.
- `opts` — additional enum4linux options, for example `-a` for all.
- `timeout` — per-call timeout in seconds.

## Output

Returns enum4linux's text output. Reconix has a reader for it, so the run becomes findings: one
per exposed share and one per enumerated user, both `LOW` (exposed surface rather than a weakness
on its own), each capped at 25 rows so a big domain cannot flood the list, and each keeping the
name it came from as evidence. A server that allows a session with an empty username and an empty
password is its own `MEDIUM` finding, an anonymous/null SMB session, carrying CWE-287 and
A05:2021 and the remediation to require authentication. The finding's target is the host from
enum4linux's target line. Output that is not enum4linux's is an unreadable-output error, not an
enumeration that found nothing.

## Risk notes

The catalog baseline is `MEDIUM`, and `risk_ops.json` lists no escalation patterns for enum4linux,
so a call stays there. Under S4 that means it waits for a person, and a call above the scope's
`max_risk` is blocked. enum4linux is not a free-shell tool, so the command check blocks a control
character or a shell metacharacter in the target or in `opts`. What it prints — users, shares,
password policy — is fact about the target, but S8 still applies to the run: the harness masks
secrets before anything is saved, logged, shown, sent to the model or stored in Qdrant. When the
scope lists allowed ports, a host target needs 137, 139, 389 and 445 all in it — the only ports
enum4linux reaches — or the call is `PORTS_OUT_OF_SCOPE`.
