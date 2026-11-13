# whatweb

## When to use

Web technology fingerprinting: it identifies the CMS (WordPress, Joomla, Drupal), web frameworks,
JavaScript libraries, analytics platforms, CDNs and server software behind a site. The spec says to
use it FIRST on any web target to understand the tech stack before running specialized tools, so it
comes after something such as httpx_probe has shown a port is serving HTTP and before the tools that
attack that stack. Its answer is what the site runs, not what is wrong with it.

## Key options

- `target` — required. A target URL or IP, for example `https://example.com`. Write any port inside
  the URL: the harness reads a bare host or IP with a port after it as a target that is not in plain
  form and blocks the call instead of cleaning it up.
- `opts` — additional whatweb options. The spec's example is `-a 3` for the aggressive level, which
  is the step beyond the passive fingerprinting its description names.
- `timeout` — per-call timeout in seconds.

## Output

A structured list of the identified technologies, with version numbers where available, in the
spec's own words. Reconix has a reader for whatweb: `read_whatweb` in
`services/api/src/reconix_api/findings/web_fingerprint.py`, wired into the `READERS` table in
`services/findings.py`. It reads the result lines — a URL, then the technologies in brackets — and
makes one finding per URL titled `Technology fingerprint: <host>`, targeted at the base URL, with
the identified technologies in the description and the raw line kept as `web_fingerprint` evidence.
The severity is `NONE` on purpose: what a site runs is a fact, and a weakness in a named version is
nuclei's or the analyst's to raise. Findings dedupe on the base URL, so a second run on the same
site adds a source instead of a new finding, and output with lines but no readable result line is
an unreadable-output error, not an empty result.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and whatweb is not
one of the free-shell tools, so nothing pushes a call to HIGH: under S4 a `LOW` call runs now,
`MEDIUM` and `HIGH` wait for a person, and anything above the scope's `max_risk` is blocked.
`risk_ops.json` has no whatweb entry, so `-a 3` in `opts` does not escalate the call — an aggressive
fingerprint is still `LOW`, no person is asked, and a `LOW` call with no escalation is always
allowed by the risk check. The scope check is what bounds it. A URL target has to match the scope,
and a scope that lists URL prefixes uses them as the only authority for URLs; when the scope also
lists allowed ports, the URL's port (written, or the scheme's default) must be one of them, and a
bare host or IP target is refused because Core cannot limit the ports such a tool reaches.
