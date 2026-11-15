# exiftool

## When to use

Reads the metadata embedded in a file — an image, PDF, Office document, audio or video: GPS,
author, software and timestamps. Use it on a file the engagement already holds, not on a host or a
URL: its one target is the path to the file to analyse. A live web target is a different job, and
the spec for whatweb says to use that FIRST on any web target to understand the tech stack.

## Key options

- `filepath` — required. The path to the file to analyse. The harness reads it as a path target, so
  it only runs when the path is inside one of the scope's approved repo folders, and any `..` in it
  is blocked as path traversal before the tool is considered.
- `opts` — additional exiftool options. The spec's only example is `-all=`, which strips metadata
  instead of reading it.
- `timeout` — per-call timeout in seconds.

## Output

All metadata fields and values, in the spec's own words. Reconix has no reader for exiftool — it is
not in the `READERS` table in `services/api/src/reconix_api/services/findings.py` — so `parse_run`
returns no findings and the masked output stays on the tool run. What comes back is read as
categories rather than values: a position, an author, the software that wrote the file, its
timestamps. Masking runs over that output before it is saved, logged, shown, sent to the AI or
stored in Qdrant, so anything credential-shaped in the metadata is hidden by a label.

## Risk notes

The catalog baseline is `LOW`, the entry is `read_only`, `destructive` is not set and exiftool is
not one of the free-shell tools (run_command, proxychains, msfconsole, smbclient), so nothing
pushes a call to HIGH: under S4 a `LOW` call runs now, `MEDIUM` and `HIGH` wait for a person, and
anything above the scope's `max_risk` is blocked. `risk_ops.json` has no exiftool entry, so no
option raises a call above that baseline — including the spec's own `-all=` example, which strips
metadata rather than reading it — and a `LOW` call with no escalation is always allowed by the risk
check. The scope check is therefore the only bound, and it is a path bound, not a network one: the
file must sit inside an approved repo folder. exiftool reads a local file, so a run sends nothing to
a network target and no port is involved.
