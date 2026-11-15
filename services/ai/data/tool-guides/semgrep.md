# semgrep

## When to use

Static analysis of source code. Semgrep matches rules against the code and reports security issues
with a file and a line, so use it for the code's own bugs, not for its dependencies or its leaked
credentials. In a Reconix code scan it reads the copy's `changed/` folder, so it runs when some file
is new or changed; the first scan, a tool set that grows, or new Kali tool versions make it a full
scan over every file. It is also the only tool that rechecks a code fix, where FIXED means Semgrep
no longer matches, not that a person verified it.

## Key options

- `path` — required. The file or directory to scan, inside the container, so a path under
  `/workspace/`. A code scan passes its own per-run copy folder here, never the stored code folder.
- `config` — the ruleset: a registry pack or a rules file. The default is `p/default`,
  a broad multi-language pack. Set the ruleset here, never through `opts`. `auto` is unavailable,
  because metrics are off.
- `opts` — extra Semgrep flags, rarely needed. Do NOT pass output or format flags (`--json`,
  `--sarif`, ...) or `--config` here: the output is already JSON and the ruleset is the `config`
  field.
- `timeout` — per-call timeout in seconds.

## Output

Returns JSON findings; the call is already configured for JSON output, so `path` alone is normally
enough. The `semgrep` mapping in `findings/json_mapping.py` makes one finding per entry of
`results[]`, titled with the rule's `check_id`, targeted at the file's `path`, located at that path
and start line, and deduped on `check_id`, path and start line, so a later run that finds the same
rule on the same line only adds itself as a source of the one finding. Severity comes from
`extra.severity`: `ERROR` is HIGH, `WARNING` is MEDIUM and `INFO` is LOW, because an INFO rule
still points at code worth a look, while newer Semgrep writes CRITICAL, HIGH, MEDIUM and LOW
directly. A severity the mapping does not know is UNKNOWN, never guessed. CWE ids come from
`extra.metadata.cwe`. The `extra` object is never kept as evidence, since it holds the matched
source lines and metavariable values, which can be the secret itself; only the message and the CWE
stay on the finding. JSON that does not parse is an unreadable-output error, not a clean scan with
nothing in it. With `analyze=true`, the default, each finding then gets an AI review: a `verdict`,
an `explanation` and a `fix_recommendation`, cached per finding, file hash and model.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain scan runs without waiting for a person, and
anything above the scope's `max_risk` is blocked (S4). `risk_ops.json` raises one call to `HIGH`
when a pattern is a substring of the call's argument values, lowercased and joined with spaces:
`--metrics`, `http://`, `https://`, `/workspace/`. The `_code_tools` note gives the reason: the 7
source code tools read the scanned code, so an option that sends it, or what was found in it, to
another server, or that reads another folder under `/workspace/`, is HIGH and a person must look at
it. A code scan's own call carries only the copy folder and no options, because that is all the
automatic code scope takes, so these patterns come from a manual call. Masking (S8) runs before the
output is saved, logged, shown, sent to the AI or stored in Qdrant. A finding the AI review calls a
likely false positive is hidden by `include_false_positives=false` only below HIGH, and never when
GITLEAKS found it; a person's FALSE_POSITIVE always hides it.
