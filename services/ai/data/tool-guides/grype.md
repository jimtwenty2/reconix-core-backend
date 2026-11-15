# grype

## When to use

Scans a directory, a container image or a Syft SBOM for known vulnerabilities, so use it for what a
project depends on rather than for the code's own bugs. It is the second dependency scanner in a
Reconix code scan next to trivy and osv_scanner, and the three are expected to overlap: the same
CVE in the same package and manifest becomes one finding with each of them as a source. In a code
scan it reads every file, and it runs on a full scan or when a manifest or lockfile changed; the
first scan, a tool set that grows, or new Kali tool versions make it a full scan. It downloads and
caches the vulnerability database, so a first call can be slow.

## Key options

- `target` — required. A directory, an image or an SBOM reference, for example `./project`,
  `alpine:3.19` or `sbom:<path>` for a Syft SBOM file. In a code scan it is the scan's own per-run
  copy folder, a path under `/workspace/`.
- `opts` — additional Grype options. Leave it empty in a code scan, whose automatic scope takes the
  scan's own calls with no options.
- `timeout` — per-call timeout in seconds. Raise it for a first run that has to fetch the database.

## Output

Returns JSON, read by `read_grype` in `findings/json_mapping.py`, one finding per entry of
`matches[]`. Each finding's target is the scanned folder joined with the package's first location,
such as `/requirements.txt` relative to that folder, while an image scan keeps the package name as
the target. The title and the description both come from `vulnerability.description`, the location
is `artifact.name` and `artifact.version`, and the severity is the tool's own
`vulnerability.severity` word, where `negligible` becomes NONE and a word the mapping does not know
becomes UNKNOWN, never guessed. CWE ids come from `vulnerability.cwes` and CVE ids from
`relatedVulnerabilities`, because grype's own id is usually a GHSA. The dedupe key is
`sca_dedupe_key` in `findings/shape.py`, shared with trivy and osv_scanner, built from a CVE id
where there is one and otherwise from the tool's own id, plus the lowercased package name and the
manifest path; the version is left out on purpose, because the tools format it differently, and
stays on the finding as evidence. A run that is BLOCKED or that fails becomes a note on the scan,
such as `GRYPE FAILED` or `GRYPE BLOCKED TOO_MANY_ACTIONS`, and the scan itself fails only when
every due tool failed.

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
