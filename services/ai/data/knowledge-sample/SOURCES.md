# Knowledge sources

This folder is a small sample (20 CVEs, 20 CWEs, 20 ATT&CK techniques, and all
10 + 10 OWASP pages), so tests and a fresh install work offline. The full set
is made by `python -m reconix_ai.knowledge.download` into `../knowledge/`,
which is never committed.

| File | Source | Licence |
|---|---|---|
| `cve.jsonl` | CISA Known Exploited Vulnerabilities catalog, https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Public domain (CC0 1.0) |
| `cwe.jsonl` | MITRE CWE, https://cwe.mitre.org | CWE Terms of Use: free to use with attribution. © The MITRE Corporation |
| `attack.jsonl` | MITRE ATT&CK Enterprise, https://attack.mitre.org | ATT&CK Terms of Use: free to use with attribution. © The MITRE Corporation |
| `owasp_top10.jsonl` | OWASP Top 10 2021, https://owasp.org/Top10/ | CC BY-SA 4.0, © OWASP Foundation |
| `owasp_api_top10.jsonl` | OWASP API Security Top 10 2023, https://owasp.org/API-Security/ | CC BY-SA 4.0, © OWASP Foundation |

The text is changed only to fit one shape (see `src/reconix_ai/knowledge/items.py`):
ATT&CK citation markers are removed, and broken apostrophes in the CISA file are fixed.
