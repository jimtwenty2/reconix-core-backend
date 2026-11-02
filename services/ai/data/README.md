# Knowledge data

Where the agent's reference knowledge comes from, how to download it, and how it gets into
Qdrant. The code is in `src/reconix_ai/knowledge/`.

## Folders

| Folder | What it holds | In git? |
|---|---|---|
| `knowledge-sample/` | A small sample of every source (20 CVEs, 20 CWEs, 20 ATT&CK techniques, all 10 + 10 OWASP pages), so tests and a fresh install work offline. Licences are in `knowledge-sample/SOURCES.md`. | Yes |
| `knowledge/` | The full download, made by the download command below | No (git-ignored) |
| `tool-guides/` | One Markdown guide per tool (`nmap.md`, `nuclei.md`, `zap.md`, `semgrep.md`, `gitleaks.md`), written by hand. Owner: Youlong. | Yes |

The ingest uses `knowledge/` when it has `.jsonl` files, otherwise `knowledge-sample/`.

## Sources we download

`python -m reconix_ai.knowledge.download` fetches all of these over HTTPS (no redirects) and
writes one JSON Lines file per source. The URLs and pins are constants in `download.py`.

| Source | File | What we take | Download URL | Page people read |
|---|---|---|---|---|
| CISA Known Exploited Vulnerabilities | `cve.jsonl` | The 1,000 newest entries | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| MITRE CWE | `cwe.jsonl` | Every weakness that is not deprecated | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip (one XML inside, about 20 MB) | https://cwe.mitre.org |
| MITRE ATT&CK Enterprise | `attack.jsonl` | Every technique that is not revoked or deprecated | `https://raw.githubusercontent.com/mitre/cti/<ATTACK_COMMIT>/enterprise-attack/enterprise-attack.json` (repo: https://github.com/mitre/cti) | https://attack.mitre.org |
| OWASP Top 10 2021 | `owasp_top10.jsonl` | The 10 risk pages (`A01:2021` to `A10:2021`) | `https://raw.githubusercontent.com/OWASP/Top10/<OWASP_TOP10_COMMIT>/2021/docs/en/<page>.md` (repo: https://github.com/OWASP/Top10) | https://top10.owasp.org |
| OWASP API Security Top 10 2023 | `owasp_api_top10.jsonl` | The 10 risk pages (`API1:2023` to `API10:2023`) | `https://raw.githubusercontent.com/OWASP/API-Security/<OWASP_API_COMMIT>/editions/2023/en/<page>.md` (repo: https://github.com/OWASP/API-Security) | https://owasp.org/API-Security/ |

**Pinned versions.** ATT&CK and both OWASP sources are pinned to one GitHub commit
(`ATTACK_COMMIT`, `OWASP_TOP10_COMMIT`, `OWASP_API_COMMIT`), so an upstream change never reaches
the agent unreviewed. Move a pin only by PR. CISA KEV and CWE have no fixed version and are taken
as they are on the day of the download.

## How to load it

Run from the repo root. The download needs internet; the ingest needs Ollama with `bge-m3` and
Qdrant running.

```bash
# 1. Download the full set into services/ai/data/knowledge/ (optional: skip to use the sample)
uv run --package reconix-ai python -m reconix_ai.knowledge.download

# 2. The embedding model
ollama pull bge-m3

# 3. Chunk, mask, embed and save into the Qdrant collection "knowledge"
uv run --package reconix-ai python -m reconix_ai.knowledge.ingest
#    add --rebuild to drop the whole collection first (also deletes user add-ons);
#    use it only when the vectors or indexes change
```

What the ingest does: each CVE, CWE and ATT&CK technique is one piece; OWASP pages and tool
guides are split at their headings (LlamaIndex `MarkdownNodeParser`); every field is masked; each
piece gets a BGE-M3 vector and a keyword vector. A normal run replaces the public knowledge and
keeps the documents people uploaded (`USER_DOC`).

## Adding a new source

These are good candidates that we do **not** download yet. Check each licence before use.

| Source | Why it helps | Where to get it |
|---|---|---|
| NVD CVE data | CVSS scores and CPEs for any CVE, not only exploited ones | API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0 (an API key raises the rate limit) |
| FIRST EPSS | How likely a CVE is to be exploited, to rank findings | https://www.first.org/epss/ (daily CSV and API at https://api.first.org/data/v1/epss) |
| MITRE CAPEC | Attack patterns that link CWE to ATT&CK | https://capec.mitre.org/data/xml/capec_latest.xml |
| OWASP Web Security Testing Guide | Step-by-step web test cases for planning | https://github.com/OWASP/wstg |
| OWASP ASVS | Verification requirements, useful for report wording | https://github.com/OWASP/ASVS |
| OWASP Cheat Sheet Series | Fix advice for findings | https://github.com/OWASP/CheatSheetSeries |
| Tool documentation | Source text for the tool guides | nmap https://nmap.org/book/man.html · nuclei https://docs.projectdiscovery.io · ZAP https://www.zaproxy.org/docs/ · semgrep https://semgrep.dev/docs/ · gitleaks https://github.com/gitleaks/gitleaks |

To add one:

1. A new value in `Source` (`items.py`) is an enum change: ask the lead first (root `AGENTS.md`
   section 10). Add it to `PUBLIC_SOURCES` too, so the ingest replaces it.
2. Write a `parse_<source>()` in `download.py` that turns the raw data into `KnowledgeItem`s, with
   a unit test on a small saved sample (no network in tests).
3. Use an HTTPS URL; pin GitHub sources to a commit.
4. Add a small sample file to `knowledge-sample/` and a row to `knowledge-sample/SOURCES.md`
   with its licence.
5. If its ids should be found exactly (like `CVE-2021-44228`), extend `REF_ID` in `search.py`.
