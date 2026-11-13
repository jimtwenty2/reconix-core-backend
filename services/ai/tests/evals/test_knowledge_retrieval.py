"""Evals 1 to 19: retrieval over the five public knowledge sources.

The 12 semantic queries are the T2 sweep (rag-retrieval-quality report §2): the entry
that defines the topic must land in the top 3. The source spread (B2) fixed the
between-source burial and gives source diversity, but 7 cases stay xfail on the full
3,121-piece corpus (public sources + tool guides) - all ingest recall, not ranking:
- "SQL injection": the sqlmap tool guide outranks the short CWE-89 text (rank 4 at
  limit 3). Defining-entry top-3 for short CWE entries needs richer stored text
  (aliases/abbreviation) - a corpus change, not a ranking patch.
- "cross site scripting", "command injection", "authentication bypass": wanted entry
  past rank 80 in dense or both lists (2026-11-13 candidate dump).
- "path traversal", "sensitive data exposure", "supply chain vulnerabilities": behind
  their own source's verbose siblings; length normalisation alone moved nothing there,
  and no better-proven change exists yet.
The exact-id cases cover all five sources and must rank first from the id boost.

Assertions are on rank and ref_id, never on score: fused RRF scores also reach 1.0
without any id in the query, so `score == 1.0` does not prove the boost fired.
"""

import pytest

B2 = pytest.mark.xfail(
    reason="B2: wanted entry not in top 3 at limit 3 (list-depth recall or same-source burial)",
    strict=False,
)
B2_GUIDE = pytest.mark.xfail(
    reason="B2 residual: with tool guides ingested, the sqlmap guide outranks the short "
    "CWE-89 text for 'SQL injection' (rank 4 at limit 3, measured 2026-11-13 on the "
    "3,121-piece corpus). Defining-entry top-3 for short CWE entries needs richer stored "
    "text (aliases/abbreviation) - an ingest-recall corpus change, not a ranking patch.",
    strict=False,
)

# (query, the ref_id that must be in the top 3) — the T2 sweep, wanted entry per row.
SEMANTIC = [
    pytest.param("SQL injection", "CWE-89", marks=B2_GUIDE),
    pytest.param("server-side request forgery", "CWE-918"),
    pytest.param("credential dumping", "T1003"),
    pytest.param("broken object level authorization", "API1:2023"),
    pytest.param("cross site scripting", "CWE-79", marks=B2),
    pytest.param("path traversal", "CWE-22", marks=B2),
    pytest.param("security misconfiguration", "A05:2021"),
    pytest.param("logging and monitoring failures", "A09:2021"),
    pytest.param("command injection", "CWE-78", marks=B2),
    pytest.param("authentication bypass", "CWE-287", marks=B2),
    pytest.param("sensitive data exposure", "CWE-200", marks=B2),
    pytest.param("supply chain vulnerabilities", "A06:2021", marks=B2),
]

# (query, the ref_id the exact-id boost must put first) — one per source, plus two
# ways of writing an id: lowercase, and inside a sentence.
EXACT_ID = [
    pytest.param("CWE-79", "CWE-79"),  # CWE
    pytest.param("CVE-2014-6278", "CVE-2014-6278"),  # CVE
    pytest.param("T1059", "T1059"),  # ATTACK
    pytest.param("A03:2021", "A03:2021"),  # OWASP_TOP10
    pytest.param("API1:2023", "API1:2023"),  # OWASP_API_TOP10
    pytest.param("cwe-89", "CWE-89"),
    pytest.param("tell me about CVE-2014-6278 Shellshock", "CVE-2014-6278"),
]


@pytest.mark.parametrize(("query", "expected"), SEMANTIC)
def test_semantic_query_surfaces_the_defining_entry(stack, query, expected):
    assert expected in stack.ranks(query, limit=3)


@pytest.mark.parametrize(("query", "expected"), EXACT_ID)
def test_exact_id_ranks_first(stack, query, expected):
    assert stack.ranks(query, limit=5)[:1] == [expected]
