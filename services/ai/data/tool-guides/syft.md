# syft

## When to use

Generates a Software Bill of Materials for a local directory or a container image: it lists the
packages and dependencies present and says nothing about whether they are vulnerable. Use it to
see what a project actually holds, and to feed the SBOM to grype as `sbom:<file>` for the
vulnerability scan. In a Reconix code scan it reads every file, and it runs on a full scan or when a
manifest or lockfile changed; the first scan, a tool set that grows, or new Kali tool versions make
it a full scan.

## Key options

- `target` — required. The directory or container image to catalogue, for example `alpine:3.19`. In
  a code scan it is the scan's own per-run copy folder, a path under `/workspace/`.
- `opts` — additional Syft options. Leave it empty in a code scan, whose automatic scope takes the
  scan's own calls with no options.
- `timeout` — per-call timeout in seconds.

## Output

Returns Syft JSON, and no findings: `READERS` in `services/findings.py` points syft at
`code_notes.read_syft`, which checks the document and returns an empty list, because a package list
holds no vulnerabilities. What the code scan keeps is a note, `SYFT <n> packages`, where `<n>` is
the length of the document's `artifacts` list. Output that is not Syft's JSON, or not JSON at all,
gives the note `SYFT OUTPUT_UNREADABLE` instead of a clean scan with nothing in it, and a run that
is BLOCKED or that fails gives a note such as `SYFT FAILED`. The masked output itself stays on the
tool run and can be read as text through `GET /code-scans/{id}/logs/syft`. Because there are no
findings, there is nothing here for the AI review to judge and nothing for a code fix to work on.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain run goes without waiting for a person, and anything
above the scope's `max_risk` is blocked (S4). `risk_ops.json` raises one call to `HIGH` when a
pattern is a substring of the call's argument values, lowercased and joined with spaces: `http://`,
`https://`, `/workspace/`. The `_code_tools` note gives the reason: the 7 source code tools read the
scanned code, so an option that sends it, or what was found in it, to another server, or that reads
another folder under `/workspace/`, is HIGH and a person must look at it. A code scan's own call
carries only the copy folder and no options, because that is all the automatic code scope takes, so
these patterns come from a manual call. Syft gives no findings, so `include_false_positives` has
nothing of its own to hide; where the filter does apply, an AI likely false positive is hidden only
below HIGH, never for GITLEAKS, and always for a person's FALSE_POSITIVE.
