# wpscan

## When to use

The dedicated WordPress security scanner: it enumerates plugins, themes and users with the
vulnerabilities known for them, and reports the WordPress version. Use it only on a confirmed
WordPress target. nuclei is the catalog's primary web and service scanner and the one to use for
everything that is not WordPress-specific, nikto sweeps a web server's known issues, testssl takes
the TLS endpoint and ZAP the web scan.

## Key options

- `url` — required. The WordPress site URL, for example `http://example.com`.
- `opts` — additional wpscan options, as in the spec's own example
  `--enumerate vp,u --api-token ...`: the enumeration says what to enumerate, and the API token is
  for the vulnerability data. The spec calls these additional and names no default they replace,
  unlike nuclei's `opts`. A token is a secret, so name the option in a proposed action and never
  write a value for it into a plan, a guide or an example.
- `timeout` — per-call timeout in seconds. The spec names no default; raise it if enumerating a
  large site needs longer.

## Output

The WordPress version, the enumerated items and the findings. Reconix has no reader for wpscan —
it is not in the `READERS` table in `services/findings.py` — so nothing is parsed into finding
rows and Reconix assigns no severity to what wpscan reports. The masked output is still kept on
the tool run, and that is where the version, the plugins, themes and users and the reported
vulnerabilities are read. A run that saved no findings is not a clean site; it is a run no reader
parsed.

## Risk notes

The catalog baseline is `MEDIUM`, so a wpscan call waits for a person and anything above the
scope's `max_risk` is blocked with HTTP 422. `risk_ops.json` lists no escalation for wpscan, so no
option value lifts a call above that baseline. wpscan is marked neither `read_only` nor
`destructive` in the catalog. It scans a live site over the network, so the scope check — approved
targets, exclusions, time window, allowed tools and max risk — is what keeps it on the site the
person approved. The API token the spec asks for travels as an argument value of the call, which
is one more reason to name the option and leave the value to the person.
