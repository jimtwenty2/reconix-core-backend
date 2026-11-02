"""The pure parts of code scans: paths, evidence fields and the source line."""

import json
from uuid import uuid4

import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import ApprovedScope
from reconix_api.services.code_scans import (
    _int,
    _line,
    _proof,
    excluded_folders,
    may_hold_secret,
    relative_path,
)

PREFIX = "/workspace/code/abc/"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (f"{PREFIX}src/app.js", "src/app.js"),
        ("src/app.js", "src/app.js"),  # a tool that reports relative paths
        (f"{PREFIX}../other/app.js", None),
        ("/workspace/code/other/app.js", None),  # another session's code
        ("/etc/passwd", None),
        ("172.20.0.5", "172.20.0.5"),  # not a path at all: kept as a plain name
        ("", None),
    ],
)
def test_relative_path(target, expected):
    assert relative_path(target, PREFIX) == expected


def test_proof_reads_only_a_json_object():
    assert _proof(json.dumps({"check_id": "x"})) == {"check_id": "x"}
    assert _proof("[1, 2]") == {}
    assert _proof("not json") == {}
    assert _proof(None) == {}


def test_int_takes_the_first_whole_line_number():
    semgrep = {"start": {"line": 4}, "end": {"line": 6}}
    gitleaks = {"StartLine": 9}
    assert _int(semgrep, ("start", "line"), ("StartLine",)) == 4
    assert _int(gitleaks, ("start", "line"), ("StartLine",)) == 9
    assert _int({"start": {"line": 0}}, ("start", "line")) is None
    assert _int({"start": {"line": "4"}}, ("start", "line")) is None
    assert _int({"start": 4}, ("start", "line")) is None


def test_line_reads_one_line_trimmed(tmp_path):
    file = tmp_path / "app.js"
    file.write_bytes(b"first\n   second  \n\xff third\n")
    assert _line(file, 2) == "second"
    assert _line(file, 3) == "� third"
    assert _line(file, 9) == ""


@pytest.mark.parametrize(
    ("tools", "rule_id", "cwe_ids", "expected"),
    [
        (["GITLEAKS"], "generic-api-key", [], True),
        (["SEMGREP"], "javascript.jsonwebtoken.security.jwt-hardcode", [], True),
        (["SEMGREP"], "generic.secrets.security.detected-private-key", [], True),
        (["SEMGREP"], "python.lang.hardcoded-password", [], True),
        (["SEMGREP"], "some.rule", ["CWE-798"], True),
        (["SEMGREP"], "javascript.lang.security.audit.eval-detected", ["CWE-95"], False),
        (["SEMGREP"], None, [], False),
    ],
)
def test_lines_that_may_be_a_secret_get_no_snippet(tools, rule_id, cwe_ids, expected):
    assert may_hold_secret(tools, rule_id, cwe_ids) is expected


def test_excluded_folders_are_made_relative_to_the_code():
    target = "/workspace/code/abc"
    scope = ApprovedScope(
        assessment_id=uuid4(),
        repo_paths=[target],
        excluded_targets=[f"{target}/node_modules", f"{target}/.git", "/workspace/code/abcd"],
    )
    assert excluded_folders(scope, target) == [".git", "node_modules"]


@pytest.mark.parametrize("excluded", ["/workspace/code/abc", "/workspace/code/abc/"])
def test_a_scope_that_excludes_the_whole_code_is_refused(excluded):
    target = "/workspace/code/abc"
    scope = ApprovedScope(assessment_id=uuid4(), repo_paths=[target], excluded_targets=[excluded])
    with pytest.raises(ApiError) as error:
        excluded_folders(scope, target)
    assert error.value.code == "CODE_EXCLUDED"
