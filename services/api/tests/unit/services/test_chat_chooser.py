import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from reconix_api.schemas.code import CodeFindingOut
from reconix_api.schemas.vscode_chat import FunctionName
from reconix_api.services.chat_chooser import (
    MAX_COMMAND_CHARS,
    ProviderWords,
    choose,
    fix_targets,
    provider_words,
)


def finding(code: str, path: str, severity: str, status: str = "OPEN") -> CodeFindingOut:
    return CodeFindingOut(
        finding_id=uuid4(),
        code=code,
        title=f"{code} title",
        target=f"/workspace/code/s/{path}",
        description="",
        severity_status=severity,
        cvss_score=None,
        cwe_ids=[],
        owasp_id=[],
        cve_ids=[],
        impact=None,
        remediation=None,
        validation_status="UNCONFIRMED",
        finding_status=status,
        reviewed_by=None,
        reviewed_at=None,
        created_at=datetime.now(UTC),
        assessment_id=uuid4(),
        path=path,
        line=1,
        end_line=1,
        rule_id=None,
        snippet=None,
        file_sha256=None,
    )


SQL = finding("RCX-001", "src/routes/users.js", "CRITICAL")
XSS = finding("RCX-002", "src/routes/notes.js", "HIGH")
LEAK = finding("RCX-003", "src/routes/users.js", "HIGH")
NOISE = finding("RCX-004", "src/app.js", "HIGH", status="FALSE_POSITIVE")
FINDINGS = [XSS, LEAK, NOISE, SQL]
PROVIDERS = [
    ProviderWords(uuid4(), provider_words("Reconix default", "reconix-default", "RECONIX")),
    ProviderWords(uuid4(), provider_words("GPT-4o", "gpt-4o", "OPENAI")),
    ProviderWords(uuid4(), provider_words("Qwen2.5 Coder", "qwen2.5-coder", "OLLAMA")),
]


def chosen(text: str, findings=FINDINGS, providers=PROVIDERS):
    return choose(text, lambda: findings, lambda: providers)


def name(text: str) -> FunctionName | None:
    call = chosen(text)
    return call.name if call else None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Scan this project", FunctionName.START_SCAN),
        ("please analyze the workspace", FunctionName.START_SCAN),
        ("scan it again", FunctionName.START_SCAN),
        ("rescan", FunctionName.START_SCAN),
        ("stop", FunctionName.CANCEL_SCAN),
        ("Cancel the scan", FunctionName.CANCEL_SCAN),
        ("scan status", FunctionName.SCAN_STATUS),
        ("is the scan done?", FunctionName.SCAN_STATUS),
        ("Fix all high findings", FunctionName.PROPOSE_FIX),
        ("Summarize all findings", FunctionName.SUMMARIZE_FINDINGS),
        ("show findings", FunctionName.LIST_FINDINGS),
        ("list the high findings in users.js", FunctionName.LIST_FINDINGS),
        ("explain RCX-002", FunctionName.EXPLAIN_FINDING),
        ("switch to gpt-4o", FunctionName.SWITCH_MODEL),
    ],
)
def test_clear_commands_choose_a_function(text, expected):
    assert name(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "What are the most serious problems?",
        "check this finding",
        "How do I fix the SQL injection?",
        "what did the scan find in this project?",
        "use this to learn",
        "stop worrying, what is RCX-001?",
        "why does https://github.com/a/b fail?",
        "scan https://github.com/owner/repo",
        "explain RCX-999",
        "summary of the auth module design",
        "check this code for SQL injection",
        "analyze this function",
        "can you give me a summary?",
        "switch to the claude model",
        "   ",
    ],
)
def test_questions_and_unclear_messages_go_to_the_agent(text):
    assert name(text) is None


def test_a_long_message_is_never_a_command():
    assert name("scan this project " + "x" * MAX_COMMAND_CHARS) is None
    assert name(" " * MAX_COMMAND_CHARS + "stop") is None  # padding does not hide the length


def test_findings_and_providers_are_loaded_only_when_a_rule_needs_them():
    def never():
        raise AssertionError("loaded")

    assert choose("scan this project", never, never).name == FunctionName.START_SCAN
    assert choose("What is XSS?", never, never) is None


@pytest.mark.parametrize(
    "text",
    [
        "use a" + " " * 20000 + "b",
        "show " + " " * 20000 + "findings",
        "use a" + " " * (MAX_COMMAND_CHARS - 6) + "b",
        "show " + "findings " * 30,
    ],
)
def test_no_message_makes_the_matching_slow(text):
    started = time.perf_counter()
    chosen(text)
    assert time.perf_counter() - started < 0.05


def test_a_scan_from_scratch_is_full():
    assert chosen("Scan everything again from scratch").arguments == {"full": True}
    assert chosen("scan this project").arguments == {}


def test_list_names_one_severity_and_one_file():
    call = chosen("list the high findings in users.js")
    assert call.arguments == {"severity": "HIGH", "path": "src/routes/users.js"}


def test_fix_picks_open_findings_by_severity_most_serious_first():
    assert fix_targets("fix the critical and high ones", FINDINGS) == [SQL, XSS, LEAK]
    assert fix_targets("fix all high findings", FINDINGS) == [XSS, LEAK]
    assert fix_targets("fix users.js", FINDINGS) == [SQL, LEAK]
    assert NOISE not in fix_targets("fix everything", FINDINGS)


def test_a_finding_named_by_code_or_id_is_picked_even_when_not_open():
    assert fix_targets("fix rcx-004", FINDINGS) == [NOISE]
    assert fix_targets(f"fix {XSS.finding_id} and RCX-001", FINDINGS) == [XSS, SQL]


def test_fix_without_a_target_names_no_findings():
    call = chosen("fix the bug")
    assert (call.name, call.arguments) == (FunctionName.PROPOSE_FIX, {"finding_ids": []})


def test_models_match_whole_words_only():
    call = chosen("use the ollama model")
    assert call.arguments == {"llm_provider_id": str(PROVIDERS[2].llm_provider_id)}
    assert chosen("use model a") is None
