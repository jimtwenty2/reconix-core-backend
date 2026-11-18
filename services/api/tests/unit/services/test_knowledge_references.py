from reconix_api.services.knowledge_references import MAX_REFERENCES, references


def test_exact_ids_are_found_and_written_one_way():
    [*refs] = references(["cve-2021-44228 and CWE 89, A10:2021, API1:2023, T1059.001"])
    ids = {(r.type, r.ref_id) for r in refs}
    assert {
        ("CVE", "CVE-2021-44228"),
        ("CWE", "CWE-89"),
        ("OWASP", "A10:2021"),
        ("OWASP", "API1:2023"),
        ("ATTACK", "T1059.001"),
    } <= ids


def test_each_is_counted_once_per_passage_most_mentioned_first():
    refs = references(["CWE-79 CWE-79 xss", "CWE-79", "CWE-89"])
    counts = {r.ref_id: r.count for r in refs}
    assert counts == {"CWE-79": 2, "CWE-89": 1, "cross-site-scripting": 1}
    assert refs[0].ref_id == "CWE-79"


def test_tools_are_whole_words_and_never_internal_helpers():
    ids = {r.ref_id for r in references(["run nmap, then nucleus and run_command"])}
    assert "NMAP" in ids
    assert "NUCLEI" not in ids  # "nucleus" is not nuclei
    assert "RUN_COMMAND" not in ids


def test_topics_come_from_plain_words():
    ids = {r.ref_id for r in references(["Found an SSRF and a path traversal (../etc/passwd)."])}
    assert {"server-side-request-forgery", "path-traversal"} <= ids

    overlap = {r.ref_id for r in references(["Remove default credentials before launch."])}
    assert {"security-misconfiguration", "secrets-in-code"} <= overlap


def test_nothing_found_is_empty_and_the_list_is_capped():
    assert references(["Rotate the staging keys on Friday."]) == []
    many = [" ".join(f"CWE-{n}" for n in range(1, 200))]
    assert len(references(many)) == MAX_REFERENCES


def test_spans_point_at_the_words_and_agree_with_the_counts():
    from reconix_api.services.knowledge_references import spans

    text = "Use SQLMap for SQL Injection (CWE-89); see CVE-2021-44228 and T1190."
    found = spans(text)
    assert [(s.type, text[s.start : s.end]) for s in found] == [
        ("TOOL", "SQLMap"),
        ("TOPIC", "SQLMap"),  # sqlmap is also one of the SQL injection topic's words
        ("TOPIC", "SQL Injection"),
        ("CWE", "CWE-89"),
        ("CVE", "CVE-2021-44228"),
        ("ATTACK", "T1190"),
    ]
    assert {(s.type, s.ref_id) for s in found} == {(r.type, r.ref_id) for r in references([text])}
