# osv_scanner

## When to use

Scans a local project directory for dependencies that are known-vulnerable or known-malicious and
compromised, using OSV-Scanner against the OSV database, which includes the OpenSSF
malicious-package advisories with ids like `MAL-*`. Use it for the supply-chain side of what a
project depends on, the part trivy and grype do not cover, since it reads lockfiles and manifests
and not the code itself. In a Reconix code scan it reads every file, and it runs on a full scan or
when a manifest or lockfile changed; the first scan, a tool set that grows, or new Kali tool
versions make it a full scan.

## Key options

- `path` — required. The local project directory to scan, inside the container, so a path under
  `/workspace/`. A code scan passes its own per-run copy folder here.
- `opts` — additional OSV-Scanner options, for example `--lockfile <path>` to scan one lockfile or
  `--no-ignore`. Leave it empty in a code scan, whose automatic scope takes the scan's own calls
  with no options.
- `timeout` — per-call timeout in seconds.

## Output

Returns JSON, read by `findings/osv.py`, which gives one finding per vulnerability per package.
OSV-Scanner keeps the package and the severity outside the vulnerability, so the reader takes the
package from the vulnerability's parent and the severity from the CVSS score on the group that
lists the vulnerability's id: 9.0 and above is CRITICAL, 7.0 and above HIGH, 4.0 and above MEDIUM,
0.1 and above LOW, below that NONE, and a score the tool does not give is UNKNOWN, never guessed.
The target is the manifest osv_scanner read, the absolute `source.path` of the result, and the
package name when there is none. The title is the advisory's summary, or the first line of its
details, with the package name appended, and the evidence is the vulnerability itself as
`osv_vulnerability`, located at the package, its version and that manifest. CVE ids are taken from
the vulnerability's id and its aliases, and the dedupe key is `sca_dedupe_key` in
`findings/shape.py`, shared with trivy and grype, so the same CVE in the same package and manifest
collapses into one finding with each tool listed as a source. Output that is not osv-scanner's JSON
is an unreadable-output error, not a clean scan with nothing in it.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain scan runs without waiting for a person, and
anything above the scope's `max_risk` is blocked (S4). `risk_ops.json` raises one call to `HIGH`
when a pattern is a substring of the call's argument values, lowercased and joined with spaces:
`http://`, `https://`, `/workspace/`. The `_code_tools` note gives the reason: the 7 source code
tools read the scanned code, so an option that sends it, or what was found in it, to another
server, or that reads another folder under `/workspace/`, is HIGH and a person must look at it. A
code scan's own call carries only the copy folder and no options, because that is all the
automatic code scope takes, so these patterns come from a manual call. A finding the AI review
calls a likely false positive is hidden by `include_false_positives=false` only below HIGH, and
never when GITLEAKS found it; a person's FALSE_POSITIVE always hides it.
