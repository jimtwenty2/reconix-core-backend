# trivy

## When to use

Scans a local directory's dependency manifests and lockfiles for known vulnerabilities, and its
misconfig scanner also reports IaC and configuration problems in files such as a Dockerfile, a
compose file, Kubernetes manifests and Terraform. Use it for what a project depends on, not for the
code's own bugs. In a Reconix code scan it reads every file, and it runs on a full scan or when a
manifest or lockfile changed; the first scan, a tool set that grows, or new Kali tool versions make
it a full scan. It downloads and caches the vulnerability database, so a first call can be slow.

## Key options

- `path` — required. The local project directory to scan, inside the container, so a path under
  `/workspace/`. A code scan passes its own per-run copy folder here.
- `opts` — additional Trivy filesystem options. Leave it empty in a code scan, whose automatic
  scope takes the scan's own calls with no options.
- `timeout` — per-call timeout in seconds. Raise it for a first run that has to fetch the database.

## Output

Returns JSON, read by `read_trivy` in `findings/json_mapping.py`. It walks `Results[]` for
`Vulnerabilities[]` and for `Misconfigurations[]`, where only a check whose `Status` is `FAIL`
becomes a finding, so a failed misconfiguration is reported and a passed one is not. A
vulnerability finding's target is the manifest file: the scanned folder (`ArtifactName`, when
`ArtifactType` is filesystem) joined with the parent result's `Target`, such as `requirements.txt`
or `Dockerfile`; any other artifact, an image or a repository URL, keeps the package name as the
target. Its title is `Title`, its location `PkgName` and `InstalledVersion`, its severity the
tool's own `Severity` word (INFO becomes NONE), its description `Description`, its CWE ids
`CweIDs` and its CVE id `VulnerabilityID`. A misconfig finding uses the `trivy_misconfig` mapping,
located at `AVDID` and `CauseMetadata.StartLine`, with `Resolution` as the remediation. Dependency
findings are keyed by `sca_dedupe_key` in `findings/shape.py`, the one key trivy, grype and
osv_scanner share, so the same CVE in the same package and manifest is one finding with each tool
listed as a source rather than three findings. The version stays out of that key on purpose,
because the tools format it differently, and stays on the finding as evidence. A severity the
mapping does not know is UNKNOWN, never guessed.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain scan runs without waiting for a person, and
anything above the scope's `max_risk` is blocked (S4). `risk_ops.json` raises one call to `HIGH`
when a pattern is a substring of the call's argument values, lowercased and joined with spaces:
`--server`, `--token`, `--db-repository`, `--java-db-repository`, `--checks-bundle-repository`,
`http://`, `https://`, `/workspace/`. The `_code_tools` note gives the reason: the 7 source code
tools read the scanned code, so an option that sends it, or what was found in it, to another
server, or that reads another folder under `/workspace/`, is HIGH and a person must look at it. A
code scan's own call carries only the copy folder and no options, because that is all the
automatic code scope takes, so these patterns come from a manual call. A finding the AI review
calls a likely false positive is hidden by `include_false_positives=false` only below HIGH, and
never when GITLEAKS found it; a person's FALSE_POSITIVE always hides it.
