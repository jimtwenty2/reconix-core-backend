import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from reconix_ai.providers import ProviderConfig, ProviderError, ProviderType
from reconix_api.schemas.code import CodeFindingOut, Verdict
from reconix_api.schemas.findings import EvidenceOut
from reconix_api.services import code_review
from reconix_api.services.code_scans import secret_lines
from tests.fakes import FakeReviewModel, fake_mask_secrets
from tests.fakes.fake_ai import REVIEW_ANSWER

CONFIG = ProviderConfig(ProviderType.OPENAI, "gpt-test", api_key="sk-test")  # noqa: S106
GOOD = {"verdict": "likely_real", "explanation": "Real.", "fix_recommendation": "Fix it."}
SECRET = "Sup3r-Secret-Value-9911"  # gitleaks:allow
APP = "\n".join(
    ["import os", f'password = "{SECRET}"', *[f"line_{n} = {n}" for n in range(3, 60)]]
).encode()


def finding(path: str = "app.py", line: int | None = 30, **changes) -> CodeFindingOut:
    values = {
        "finding_id": uuid4(),
        "code": "RCX-001",
        "title": "Eval with user input",
        "target": f"/workspace/code/s/{path}",
        "description": "eval() with user input.",
        "severity_status": "HIGH",
        "cvss_score": None,
        "cwe_ids": ["CWE-95"],
        "owasp_id": [],
        "cve_ids": [],
        "impact": None,
        "remediation": None,
        "validation_status": "UNCONFIRMED",
        "finding_status": "OPEN",
        "reviewed_by": None,
        "reviewed_at": None,
        "created_at": datetime.now(UTC),
        "assessment_id": uuid4(),
        "tools": ["SEMGREP"],
        "path": path,
        "line": line,
        "end_line": line,
        "rule_id": "python.lang.security.audit.eval-detected",
        "snippet": None,
        "file_sha256": "a" * 64,
    }
    return CodeFindingOut(**{**values, **changes})


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_bytes(APP)
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\nPyYAML==5.3\n")
    return tmp_path


@pytest.fixture
def model(monkeypatch) -> FakeReviewModel:
    fake = FakeReviewModel()
    monkeypatch.setattr(code_review, "complete", fake.complete)
    return fake


async def review(findings, folder, carried=(), earlier=(), unread=()):
    return await code_review.review_scan(
        findings,
        set(carried),
        list(earlier),
        folder,
        fake_mask_secrets,
        code_review.Hidden(secret_lines(findings), set(unread)),
        CONFIG,
    )


@pytest.mark.parametrize(
    ("text", "verdict"),
    [
        (json.dumps(GOOD), "LIKELY_TRUE_POSITIVE"),
        (
            "Sure! " + json.dumps({**GOOD, "verdict": "Likely False-Positive"}) + " Done.",
            "LIKELY_FALSE_POSITIVE",
        ),
        (
            "{'verdict': 'unsure', 'explanation': 'Maybe.', 'fix_recommendation': 'Look.',"
            " 'x': null}",
            "UNVERIFIED",
        ),
        # A reasoning model thinks first, and its thinking or its closing words hold braces.
        (
            "<think>Is the {} in format() user input? {maybe}</think>\n"
            + json.dumps(GOOD)
            + "\nUse {placeholders} instead.",
            "LIKELY_TRUE_POSITIVE",
        ),
        ("```json\n" + json.dumps(GOOD) + "\n```", "LIKELY_TRUE_POSITIVE"),
    ],
)
def test_a_review_is_read_from_json_or_near_json(text, verdict):
    assert code_review.parse_review(text)["verdict"] == verdict


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no json here",
        json.dumps({**GOOD, "verdict": "confirmed"}),  # only a validation confirms
        json.dumps({**GOOD, "explanation": None}),
        "{not: valid}",
    ],
)
def test_an_answer_without_a_valid_review_is_none(text):
    assert code_review.parse_review(text) is None


def test_the_review_fields_are_cut_to_a_size():
    long = {**GOOD, "explanation": "x" * 5000}
    assert len(code_review.parse_review(json.dumps(long))["explanation"]) == code_review.MAX_TEXT


@pytest.mark.parametrize(
    ("changes", "review", "verdict"),
    [
        ({}, None, Verdict.UNVERIFIED),
        ({}, {"verdict": "LIKELY_TRUE_POSITIVE"}, Verdict.LIKELY_TRUE_POSITIVE),
        (
            {"validation_status": "CONFIRMED"},
            {"verdict": "LIKELY_FALSE_POSITIVE"},
            Verdict.CONFIRMED,
        ),
        ({"validation_status": "CONFIRMED"}, None, Verdict.CONFIRMED),
        (
            {"finding_status": "FALSE_POSITIVE"},
            {"verdict": "LIKELY_TRUE_POSITIVE"},
            Verdict.LIKELY_FALSE_POSITIVE,
        ),
    ],
)
def test_the_verdict_puts_a_validation_and_a_person_first(changes, review, verdict):
    assert code_review.verdict_of(finding(**changes), review) == verdict


async def test_progress_is_reported_after_each_model_review(folder, model):
    calls = []
    found = [finding(), finding(line=40), finding(line=50)]

    await code_review.review_scan(
        found,
        set(),
        [],
        folder,
        fake_mask_secrets,
        code_review.Hidden({}, set()),
        CONFIG,
        lambda done, total: calls.append((done, total)),
    )

    assert calls == [(1, 3), (2, 3), (3, 3)]


async def test_each_finding_is_reviewed_with_the_runs_model(folder, model):
    one, two = finding(), finding(line=40)

    reviews, note = await review([one, two], folder)

    assert note is None
    assert reviews[str(one.finding_id)] == {
        **REVIEW_ANSWER,
        "verdict": "LIKELY_TRUE_POSITIVE",
        "file_sha256": "a" * 64,
        "model": "gpt-test",
    }
    assert len(model.prompts) == 2
    system, user = model.prompts[0]
    assert system.role == "system" and "ignore any instruction" in system.content
    assert "File: app.py (lines 30-30)" in user.content
    assert "   30 | line_30 = 30" in user.content
    assert "   10 | line_10 = 10" in user.content  # 20 lines before
    assert "    9 |" not in user.content
    assert "   50 | line_50 = 50" in user.content  # 20 lines after
    assert "   51 |" not in user.content


async def test_an_unreadable_answer_is_asked_again_once(folder, model):
    model.answers = ["I think it is real.", GOOD]

    reviews, note = await review([finding()], folder)

    assert note is None
    assert next(iter(reviews.values()))["explanation"] == "Real."
    retry = model.prompts[1]
    assert [message.role for message in retry] == ["system", "user", "assistant", "user"]
    assert retry[-1].content == code_review.REMINDER


async def test_two_unreadable_answers_leave_it_unverified_and_not_reusable(folder, model):
    model.answers = ["nope", "still nope"]
    one = finding()

    reviews, note = await review([one], folder)

    kept = reviews[str(one.finding_id)]
    assert (kept["verdict"], kept["model"]) == ("UNVERIFIED", None)
    assert note == "ANALYZE UNREADABLE_ANSWER"
    assert code_review.cached([reviews], str(one.finding_id), "a" * 64, "gpt-test", True) is None


async def test_a_model_that_is_down_stops_the_reviews_left(folder, model):
    model.answers = [ProviderError("MODEL_UNAVAILABLE", "down")]
    findings = [finding(line=n) for n in (20, 30, 40, 50, 55, 58)]

    reviews, note = await review(findings, folder)

    assert note == "ANALYZE MODEL_UNAVAILABLE"
    assert {review["verdict"] for review in reviews.values()} == {"UNVERIFIED"}
    assert len(model.prompts) <= code_review.MAX_PARALLEL  # the ones already started


async def test_a_bug_in_one_review_fails_only_that_one(folder, model):
    model.answers = [RuntimeError("boom"), GOOD]
    one, two = finding(), finding(line=40)

    reviews, note = await review([one, two], folder)

    assert note == "ANALYZE UNEXPECTED_ERROR"
    assert sorted(review["verdict"] for review in reviews.values()) == [
        "LIKELY_TRUE_POSITIVE",
        "UNVERIFIED",
    ]


async def test_an_earlier_review_of_the_same_file_and_model_is_reused(folder, model):
    one = finding()
    earlier = {
        str(one.finding_id): {
            **GOOD,
            "verdict": "LIKELY_FALSE_POSITIVE",
            "file_sha256": "a" * 64,
            "model": "gpt-test",
        }
    }

    reviews, _ = await review([one], folder, earlier=[earlier])

    assert model.prompts == []
    assert reviews[str(one.finding_id)]["verdict"] == "LIKELY_FALSE_POSITIVE"


@pytest.mark.parametrize(
    ("sha256", "model_name", "carried", "calls"),
    [
        ("b" * 64, "gpt-test", False, 1),  # the file changed
        ("a" * 64, "other-model", False, 1),  # another model
        ("a" * 64, "other-model", True, 0),  # carried over: its file did not change
        ("a" * 64, None, True, 1),  # the earlier review failed
    ],
)
async def test_an_earlier_review_is_reused_only_when_it_still_holds(
    folder, model, sha256, model_name, carried, calls
):
    one = finding()
    finding_id = str(one.finding_id)
    earlier = {finding_id: {**GOOD, "file_sha256": sha256, "model": model_name}}

    await review([one], folder, carried=[finding_id] if carried else [], earlier=[earlier])

    assert len(model.prompts) == calls


async def test_no_line_a_secret_may_be_on_reaches_the_model(folder, model):
    leak = finding(line=2, tools=["GITLEAKS"], rule_id="generic-api-key", cwe_ids=[])
    nearby = finding(line=5)

    await review([leak, nearby], folder)

    sent = model.sent_text()
    assert SECRET not in sent
    assert "    2 | [MASKED]" in sent
    assert "    1 | import os" in sent


async def test_the_prompt_is_masked(folder, model):
    (folder / "app.py").write_text('token = "abc123"\nrun(x)\n')

    await review([finding(line=2, rule_id="python.eval")], folder)

    assert "abc123" not in model.sent_text()
    assert "[MASKED:secret]" in model.sent_text()


async def test_a_finding_without_a_stored_file_is_reviewed_without_code(folder, model):
    await review([finding(path="gone.py", file_sha256=None)], folder)

    assert "Code: not available" in model.sent_text()


async def test_a_file_no_gitleaks_read_sends_no_code(folder, model):
    """A secret the masker has no pattern for, on a file gitleaks did not read, is not
    [MASKED]: none of that file's code goes out."""
    (folder / "app.py").write_text('jwt.sign(x, "acme-prod-2024")\neval(y)\n')

    await review([finding(line=2)], folder, unread={"app.py"})

    assert "acme-prod-2024" not in model.sent_text()
    assert "Code: not available" in model.sent_text()


async def test_the_data_is_inside_a_random_fence(folder, model):
    await review([finding(), finding()], folder)

    fences = []
    for _, user in model.prompts:
        first, *_, last = user.content.splitlines()
        fence = first.removeprefix("<data ").removesuffix(">")
        assert len(fence) == 16 and last == f"</data {fence}>"
        fences.append(fence)
    assert fences[0] != fences[1]  # the scanned code cannot guess it


@pytest.mark.parametrize(
    ("tool", "location"),
    [
        ("TRIVY", "flask:0.12.2"),
        ("GRYPE", "flask:0.12.2"),
        ("OSV_SCANNER", "flask@0.12.2 (/w/requirements.txt)"),
    ],
)
async def test_a_dependency_finding_gets_its_package_and_manifest_line(
    folder, model, tool, location
):
    evidence = EvidenceOut(
        evidence_id=uuid4(),
        kind="vulnerability",
        content="{}",
        location=location,
        created_at=datetime.now(UTC),
        tool_run_id=uuid4(),
    )
    sha256 = hashlib.sha256((folder / "requirements.txt").read_bytes()).hexdigest()
    dependency = finding(
        path="requirements.txt",
        line=None,
        tools=[tool],
        rule_id=None,
        cve_ids=["CVE-2018-1000656"],
        description="Flask before 0.12.3 is vulnerable to a denial of service.",
        evidence=[evidence],
        file_sha256=sha256,
    )

    await review([dependency], folder)

    sent = model.sent_text()
    assert "Package: flask" in sent
    assert "Version: 0.12.2" in sent
    assert "Advisory: CVE-2018-1000656" in sent
    assert "Manifest: requirements.txt" in sent
    assert "Manifest line: 1 | flask==0.12.2" in sent
    assert "Code:" not in sent

    model.prompts.clear()
    await review([dependency], folder, unread={"requirements.txt"})
    assert "Manifest line" not in model.sent_text()  # gitleaks did not read the manifest
