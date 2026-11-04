import pytest

from reconix_ai.agent.answers import BadAnswer
from reconix_ai.analysis.answers import NO_ANALYSIS, NO_EVIDENCE, read_analysis, read_validation
from tests.unit.analysis.cases import CASES, Case

FTP, SSH = CASES[0], CASES[1]
FINDINGS = [FTP.finding, SSH.finding]
OUTPUTS = [FTP.output, SSH.output]


def good_answer(case: Case) -> dict:
    """What a model that follows every rule would say about one finding."""
    finding = case.finding
    return {
        "code": finding["code"],
        "explanation": f"{finding['title']} on {finding['target']}.",
        "related": [],
        "severity_status": finding["severity_status"],
        "cvss_score": None,
        "evidence": case.evidence,
        "impact": "An attacker could use it.",
        "remediation": "Fix it.",
        "cwe_ids": finding["cwe_ids"],
        "owasp_id": finding["owasp_id"],
        "cve_ids": finding["cve_ids"],
        "next_step": case.next_step and {"title": "Confirm it", **case.next_step},
        "unsure": "",
    }


def read(*answers: dict, known_ids: frozenset = frozenset(), findings=None, outputs=OUTPUTS):
    data = {"summary": "Two services matter.", "findings": list(answers)}
    return read_analysis(data, findings or FINDINGS, outputs, set(known_ids))


@pytest.mark.parametrize("value", ["CONFIRMED", "unconfirmed", " Inconclusive "])
def test_read_validation_keeps_the_three_verdicts(value) -> None:
    status, reason = read_validation({"verdict": value, "reason": "The port answers."})
    assert status == value.strip().upper()
    assert reason == "The port answers."


@pytest.mark.parametrize("value", ["MAYBE", "", None, 1, "confirmed?"])
def test_read_validation_rejects_any_other_verdict(value) -> None:
    with pytest.raises(BadAnswer):
        read_validation({"verdict": value, "reason": "x"})


def test_read_validation_reason_is_optional_text() -> None:
    status, reason = read_validation({"verdict": "INCONCLUSIVE"})
    assert status == "INCONCLUSIVE"
    assert reason == ""


def broken_answer(case: Case) -> dict:
    """The same answer with every rule broken at once."""
    return {
        **good_answer(case),
        "related": ["RCX-999", case.finding["code"]],
        "severity_status": "SEVERE",
        "cvss_score": 99,
        "evidence": "Server banner: this host is vulnerable to everything.",
        "cwe_ids": ["CWE-1", "cwe-xx"],
        "cve_ids": ["CVE-2099-0001"],  # written in a banner, not in the finding or knowledge
        "next_step": {"title": "Run it", "tool": "NMAP", "target": "x", "arguments": "-sV -p 21"},
    }


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_a_good_answer_is_kept_for_each_saved_output(case: Case) -> None:
    _, [analysis] = read(good_answer(case), findings=[case.finding], outputs=[case.output])

    assert analysis["evidence"] == case.evidence
    assert analysis["severity_status"] == case.finding["severity_status"]
    assert analysis["cwe_ids"] == case.finding["cwe_ids"]
    assert analysis["unsure"] == ""
    if case.next_step:
        assert analysis["next_step"] == {**case.next_step, "is_validation": True}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_every_rule_holds_for_each_saved_output(case: Case) -> None:
    _, [analysis] = read(broken_answer(case), findings=[case.finding], outputs=[case.output])

    assert analysis["code"] == case.finding["code"]  # 1. identify
    assert analysis["related"] == []  # 2. connect: unknown codes and itself dropped
    assert analysis["severity_status"] == "UNKNOWN"  # 3. severity
    assert analysis["cvss_score"] is None
    assert analysis["evidence"] == ""  # 4. evidence must be copied
    assert NO_EVIDENCE in analysis["unsure"]  # so a person decides
    assert analysis["cwe_ids"] == []  # 7. mapping: only known ids
    assert analysis["cve_ids"] == []
    assert analysis["next_step"] is None  # 8. a one-string command is never split


def test_summary_and_order_follow_the_input() -> None:
    summary, analyses = read(good_answer(SSH), good_answer(FTP))

    assert summary == "Two services matter."
    assert [a["code"] for a in analyses] == ["RCX-001", "RCX-002"]


def test_a_finding_the_model_skipped_goes_to_a_person() -> None:
    _, [ftp, ssh] = read(good_answer(FTP))

    assert ftp["unsure"] == ""
    assert ssh["severity_status"] == "UNKNOWN"
    assert ssh["unsure"] == NO_ANALYSIS


def test_an_unknown_code_is_dropped_and_the_first_answer_wins() -> None:
    invented = {**good_answer(FTP), "code": "RCX-999"}
    second = {**good_answer(FTP), "impact": "second answer"}

    _, analyses = read(invented, good_answer(FTP), second)

    assert [a["code"] for a in analyses] == ["RCX-001", "RCX-002"]
    assert analyses[0]["impact"] == "An attacker could use it."


@pytest.mark.parametrize(
    "data", [{}, {"findings": "none"}, {"findings": [{"code": "RCX-999"}]}, {"findings": [7]}]
)
def test_an_answer_about_no_known_finding_is_bad(data: dict) -> None:
    with pytest.raises(BadAnswer):
        read_analysis(data, FINDINGS, OUTPUTS, set())


def test_related_keeps_only_other_known_codes() -> None:
    answer = {**good_answer(FTP), "related": ["RCX-002", "RCX-002", "RCX-001", 5, "RCX-404"]}

    _, [ftp, _] = read(answer)

    assert ftp["related"] == ["RCX-002"]


@pytest.mark.parametrize(
    ("given", "kept"), [("high", "HIGH"), (" None ", "NONE"), ("INFO", "UNKNOWN"), (3, "UNKNOWN")]
)
def test_severity_is_one_of_the_six_values(given: object, kept: str) -> None:
    _, [ftp, _] = read({**good_answer(FTP), "severity_status": given})

    assert ftp["severity_status"] == kept


@pytest.mark.parametrize(
    ("given", "kept"), [(7.5, 7.5), (10, 10.0), (0, 0.0), (10.1, None), (True, None), ("9", None)]
)
def test_cvss_is_a_number_from_0_to_10(given: object, kept: float | None) -> None:
    _, [ftp, _] = read({**good_answer(FTP), "cvss_score": given})

    assert ftp["cvss_score"] == kept


def test_evidence_from_another_tool_output_still_counts() -> None:
    answer = {**good_answer(FTP), "evidence": SSH.evidence}  # the SSH line, sent too

    _, [ftp, _] = read(answer)

    assert ftp["evidence"] == SSH.evidence


def test_the_models_own_doubt_is_kept_with_the_evidence_note() -> None:
    answer = {**good_answer(FTP), "evidence": "made up", "unsure": "Version not confirmed."}

    _, [ftp, _] = read(answer)

    assert ftp["unsure"] == f"Version not confirmed. {NO_EVIDENCE}"


def test_ids_from_the_knowledge_are_kept_and_banner_ids_are_not() -> None:
    answer = {**good_answer(SSH), "cve_ids": ["cve-2008-5161", "CVE-2023-38408", "CVE-2099-1"]}

    _, [_, ssh] = read(good_answer(FTP), answer, known_ids=frozenset({"CVE-2023-38408"}))

    assert ssh["cve_ids"] == ["CVE-2008-5161", "CVE-2023-38408"]


def test_owasp_ids_must_look_like_owasp_ids() -> None:
    answer = {**good_answer(FTP), "owasp_id": ["A07:2021", "API2:2023", "Top 10"]}
    known = frozenset({"A07:2021", "API2:2023", "Top 10"})

    _, [ftp, _] = read(answer, known_ids=known)

    assert ftp["owasp_id"] == ["A07:2021", "API2:2023"]


@pytest.mark.parametrize(
    "step",
    [
        None,
        "nmap -sV 172.20.0.5",
        {"tool": "METASPLOIT", "target": "172.20.0.5", "arguments": []},
        {"tool": "NMAP", "target": "", "arguments": []},
    ],
)
def test_a_malformed_next_step_is_dropped(step: object) -> None:
    _, [ftp, _] = read({**good_answer(FTP), "next_step": step})

    assert ftp["next_step"] is None


def test_long_text_is_cut() -> None:
    _, [ftp, _] = read({**good_answer(FTP), "impact": "x" * 5000})

    assert len(ftp["impact"]) == 1500


def test_evidence_too_short_to_mean_anything_is_dropped() -> None:
    _, [ftp, _] = read({**good_answer(FTP), "evidence": "ftp"})  # in the output, but 3 chars

    assert ftp["evidence"] == ""
    assert NO_EVIDENCE in ftp["unsure"]


def test_evidence_must_be_whole_in_one_tool_result() -> None:
    across = FTP.output[-20:] + "\n" + SSH.output[:20]  # the seam between two results

    _, [ftp, _] = read({**good_answer(FTP), "evidence": across})

    assert ftp["evidence"] == ""
