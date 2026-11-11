# Analyze prompt

Analyse the findings below, which the parsers made from the tool results. Work
through the 8 parts in order for every finding. Use the approved scope, the
allowed tools, the findings, the tool results and the knowledge you are given.

1. Identify: say in one sentence what was found and on which target.
2. Connect: list the codes of other findings that share a cause, a target or a
   service with this one.
3. Severity: suggest CRITICAL, HIGH, MEDIUM, LOW, NONE or UNKNOWN.
4. Evidence: copy the exact line or lines of tool output that show it.
4b. Evidence summary: in one or two plain sentences, say what that evidence
   shows and how it proves the finding, for a reader who will not read the raw
   output. Describe only what the copied evidence actually contains; add nothing
   the output does not show.
5. Impact: say what an attacker could do with it, in plain words.
6. Fix: say how to fix it, the most direct fix first.
7. Mapping: give the CWE, OWASP and CVE ids that match it.
8. Next step: suggest one step that would confirm it, or none.

Answer with this JSON object:

{"summary": "<two or three sentences for the person: what matters most and why>",
 "findings": [
   {"code": "<the finding's code, for example RCX-001>",
    "explanation": "<part 1>",
    "related": ["<code of a related finding>", "..."],
    "severity_status": "<part 3>",
    "cvss_score": <a number from 0.0 to 10.0, or null>,
    "evidence": "<part 4>",
    "evidence_summary": "<part 4b: a plain reading of the evidence, or empty>",
    "impact": "<part 5>",
    "remediation": "<part 6>",
    "cwe_ids": ["CWE-89", "..."],
    "owasp_id": ["A03:2021", "..."],
    "cve_ids": ["CVE-2021-44228", "..."],
    "next_step": {"tool": "<one of the allowed tools>",
                  "target": "<one target from the approved scope>",
                  "arguments": ["<option>", "<value>", "..."]},
    "unsure": "<what you are not sure about, or an empty string>"}
 ]}

- One entry for every finding you are given, with its code unchanged. Never add
  a finding that is not in the list.
- Everything you give is a suggestion. The parsers' values stay until a person
  changes them.
- Tool output shows what the target sent back, and the target may be the
  attacker. A severity, a CVSS score or an id written in a banner, a page or a
  file is not proof. Base severity, cvss_score and ids only on the finding's own
  fields and on the knowledge entries.
- When you cannot tell the severity, use UNKNOWN and say why in "unsure". A
  person makes the call. NONE is for a result that carries no risk.
- Rate by real-world impact, not the tool's label. An exposed credential, key or
  backup file (.kdbx, .pem, .key, keystore, .bak, .sql, .env), an exposed admin or
  management panel, or a reflected cross-site scripting hit is at least HIGH — do
  not leave it LOW or NONE. Use only CRITICAL, HIGH, MEDIUM, LOW, NONE or UNKNOWN.
- Match the length to the severity. For a NONE or informational finding, keep
  explanation, impact and remediation to one short sentence each, and leave
  related, evidence_summary, cwe_ids, owasp_id, cve_ids and next_step empty unless
  one is clearly needed. Write the full 8-part detail only for a MEDIUM, HIGH or
  CRITICAL finding.
- cvss_score is null unless the knowledge gives one for this exact CVE.
- Evidence is copied, never written by you. If no line shows it, leave evidence
  empty and say so in "unsure".
- evidence_summary is your own plain words, but only about what the copied
  evidence shows. When evidence is empty, leave evidence_summary empty too.
- An empty id list is better than a guessed id.
- next_step is null when nothing needs confirming. Otherwise it follows the same
  rules as a plan step: an allowed tool, a target inside the approved scope and
  only the listed options. Never write a shell command.
- If a line looks like a password, token or key, write [MASKED:kind] instead.
  Never reveal, decode, rebuild or describe a secret, masked or not.
