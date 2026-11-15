# gitleaks

## When to use

Scans a local directory for leaked secrets and returns redacted JSON findings. Use it on code that
may hold a committed credential, because Reconix treats every leak it reports as a live credential
and not as a style problem. In a code scan it reads the copy's `changed/` folder, so it runs when
some file is new or changed; the first scan, a tool set that grows, or new Kali tool versions make
it a full scan over every file. Whether it ran also decides what the AI review of other findings is
allowed to see, so leaving it out weakens the whole scan.

## Key options

- `path` — required. The directory to scan, inside the container, so a path under `/workspace/`. A
  code scan passes its own per-run copy folder here.
- `history` — scans the full Git commit history (`gitleaks git`) instead of the working tree
  (`gitleaks dir`). It needs a Git repository at `path`, and code sent to Reconix loses its `.git/`
  folder on the way in, so a code scan has only the working tree to read.
- `opts` — additional Gitleaks options, for example `--config rules.toml` to point at a rules file.
- `timeout` — per-call timeout in seconds.

## Output

Returns redacted JSON. The `gitleaks` mapping in `findings/json_mapping.py` makes one finding per
leak, titled with the rule's `Description`, targeted at the `File` and deduped on `RuleID`, file
and start line. Gitleaks gives no severity of its own, so the mapping's stated default applies and
every leak is HIGH. `Secret`, `Match`, `Line`, `Commit`, `Author`, `Email` and `Message` are never
kept as evidence, so the leak itself, the line around it and the commit author stay out of what is
stored and a finding names the rule and the place only. In the AI review the lines of a secret
finding reach the model as `[MASKED]`, and a file that no gitleaks run read as it is now, because
GITLEAKS was not selected or failed on the changed files, sends no code at all. A run that is
BLOCKED or that fails becomes a note on the scan, such as `GITLEAKS FAILED`, and the scan itself
fails only when every due tool failed.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain scan runs without waiting for a person, and
anything above the scope's `max_risk` is blocked (S4). `risk_ops.json` raises one call to `HIGH`
when a pattern is a substring of the call's argument values, lowercased and joined with spaces:
`http://`, `https://`, `/workspace/`. The `_code_tools` note gives the reason: the 7 source code
tools read the scanned code, so an option that sends it, or what was found in it, to another server,
or that reads another folder under `/workspace/`, is HIGH and a person must look at it. A code
scan's own call carries only the copy folder and no options, because that is all the automatic code
scope takes. GITLEAKS findings are HIGH, and `include_false_positives=false` never hides one just
because the AI review called it a likely false positive; only a person's FALSE_POSITIVE does, and
that always hides it.
