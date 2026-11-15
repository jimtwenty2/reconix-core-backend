# httpx_probe

## When to use

Probes HTTP services with ProjectDiscovery's httpx — the spec is explicit that this is not the
Python httpx client — and reports status code, title, tech and more for a target. Use it to check
quickly which hosts or ports are serving HTTP, after a port scan such as nmap and before the web
tools: whatweb fingerprints the stack behind one URL and is the spec's FIRST tool on a web target.
It answers whether a web service is there, not what is wrong with it.

## Key options

- `target` — required. A target URL, host or `host:port`; the spec's example is
  `http://juice-shop:3000`. Write the port inside a URL: the harness reads a bare `host:port` as a
  domain that is not in plain form and blocks the call instead of cleaning the target up.
- `opts` — additional httpx options. The spec's example is `-title -tech-detect -status-code`, and
  it names `-json` for JSON output per probe.
- `timeout` — per-call timeout in seconds.

## Output

One line per probe, or JSON with `-json` in `opts`, in the spec's own words. Reconix has a reader:
`read_httpx` in `services/api/src/reconix_api/findings/web_fingerprint.py`, wired into the `READERS`
table in `services/findings.py`. It reads the plain-text lines that start with `http`, takes the
bracketed fields (status, length, title, then the technologies) and makes one finding per URL titled
`Technology fingerprint: <host>`, targeted at the base URL, with the title and technologies in the
description and the raw line kept as `web_fingerprint` evidence. The severity is `NONE`: what a site
runs is a fact, not a weakness. Findings dedupe on the base URL, so a repeat probe adds a source
instead of a new finding. Output with lines but no result line the reader can use is an
unreadable-output error, and that is what a `-json` run gives it — leave `-json` out when you want
findings.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and httpx_probe is
not one of the free-shell tools, so nothing pushes a call to HIGH: under S4 a `LOW` call runs now,
`MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked.
`risk_ops.json` has no httpx_probe entry, so no option escalates a call and the risk check always
allows it. The spec describes probing HTTP services, so this one does contact the target, unlike
subfinder or theHarvester. The scope check is what bounds it: when the scope lists allowed ports, a
URL target's port (written, or the scheme's default) must be one of them, and a bare host target is
refused because Core cannot limit the ports such a tool reaches — so the bare-host form only works
in a scope with no allowed ports.
