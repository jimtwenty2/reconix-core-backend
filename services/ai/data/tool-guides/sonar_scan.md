# sonar_scan

## When to use

Runs the SonarScanner CLI against a local project directory and reports the analysis to the
SonarQube server inside the Kali container. It analyses the whole project tree and gives Reconix no
findings, so it is not a substitute for semgrep, gitleaks or the dependency scanners. In a Reconix
code scan it reads every file, and it runs when anything changed, so it is due on more scans than
any other code tool; the first scan, a tool set that grows, or new Kali tool versions make it a
full scan. Run `sonarqube-bootstrap` once first, which starts the server and writes the scanner's
host URL and token, and after that a bare `path` scans out of the box because the project key and
sources are defaulted.

## Key options

- `path` — required. The local project directory to scan, which the scanner takes as
  `sonar.projectBaseDir`. In a code scan it is the scan's own per-run copy folder, a path under
  `/workspace/`.
- `opts` — additional SonarScanner `-D` properties, for example `-Dsonar.projectKey=my-key`. Leave
  it empty in a code scan, whose automatic scope takes the scan's own calls with no options.
- `timeout` — per-call timeout in seconds.

## Output

Returns the scanner's log text, not JSON. No reader in `READERS` in `services/findings.py` turns it
into findings, so a run saves none; what the code scan keeps is a note from
`findings/code_notes.py`. The note is `SONAR_SCAN OK`, with the dashboard URL appended when the log
prints one, when the log holds `EXECUTION SUCCESS` or `ANALYSIS SUCCESSFUL`, and `SONAR_SCAN FAILED`
otherwise. A run that is BLOCKED or that fails gives its own note, `SONAR_SCAN BLOCKED <reason>` or
`SONAR_SCAN FAILED`, and the scan itself fails only when every due tool failed. The masked log
stays on the tool run and can be read as text through `GET /code-scans/{id}/logs/sonar_scan`, which
is how a person sees what the analysis said. Because there are no findings, there is nothing here
for the AI review to judge and nothing for a code fix to work on.

## Risk notes

The catalog's baseline risk is `LOW`, so a plain scan runs without waiting for a person, and
anything above the scope's `max_risk` is blocked (S4). `risk_ops.json` raises one call to `HIGH`
when a pattern is a substring of the call's argument values, lowercased and joined with spaces:
`sonar.host.url`, `sonar.token`, `sonar.login`, `sonar.password`, `sonar.projectbasedir`,
`sonar.sources`, `http://`, `https://`, `/workspace/`. The `_code_tools` note gives the reason: the
7 source code tools read the scanned code, so an option that sends it, or what was found in it, to
another server, or that reads another folder under `/workspace/`, is HIGH and a person must look at
it. Pointing the scanner at another server, or setting its credentials or its scanned folders, is
exactly such an option, and `sonarqube-bootstrap` already writes the server and its credentials,
so a bare `path` call passes none of them. A code scan's own call carries only the copy folder and
no options, because that is all the automatic code scope takes. This tool gives no findings, so
`include_false_positives` has nothing of its own to hide; where the filter does apply, an AI likely
false positive is hidden only below HIGH, never for GITLEAKS, and always for a person's
FALSE_POSITIVE.
