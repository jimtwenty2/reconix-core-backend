"""The pure parts of code scans: paths, evidence fields, the source line, which tools a
scan runs and what the next scan compares with."""

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import ApprovedScope, ToolName
from reconix_api.schemas.code import CODE_TOOLS, CodeScanIn
from reconix_api.services.code_scans import (
    _int,
    _line,
    _proof,
    _under,
    baseline,
    changes,
    due_tools,
    excluded_folders,
    is_code_folder_scope,
    is_manifest,
    may_hold_secret,
    relative_path,
    scan_tools,
    unread_by_gitleaks,
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


# ---------------------------------------------------------------------------
# Which tools a scan runs
# ---------------------------------------------------------------------------

ALL = [str(tool) for tool in CODE_TOOLS]
DEPENDENCY = {"TRIVY": "all", "GRYPE": "all", "OSV_SCANNER": "all", "SYFT": "all"}


def test_a_full_scan_runs_every_tool():
    due = due_tools(ALL, {"src/app.py"}, set(), full=True)

    assert due == {"SEMGREP": "changed", "GITLEAKS": "changed", **DEPENDENCY, "SONAR_SCAN": "all"}


def test_a_changed_source_file_runs_semgrep_gitleaks_and_sonar():
    due = due_tools(ALL, {"src/app.py"}, set(), full=False)

    assert due == {"SEMGREP": "changed", "GITLEAKS": "changed", "SONAR_SCAN": "all"}


@pytest.mark.parametrize(
    "manifest", ["requirements.txt", "api/requirements-dev.txt", "web/package-lock.json", "go.sum"]
)
def test_a_changed_manifest_runs_the_dependency_tools(manifest):
    due = due_tools(ALL, {manifest}, set(), full=False)

    assert DEPENDENCY.items() <= due.items()


@pytest.mark.parametrize(
    "iac", ["Dockerfile", "Dockerfile.prod", "docker-compose.yml", "infra/main.tf"]
)
def test_a_changed_iac_file_runs_trivy_for_misconfig_not_the_other_sca_tools(iac):
    due = due_tools(ALL, {iac}, set(), full=False)

    assert due.get("TRIVY") == "all"  # trivy scans IaC/config misconfig
    # the other dependency scanners have nothing to do on a Dockerfile/Terraform change
    assert "GRYPE" not in due and "OSV_SCANNER" not in due and "SYFT" not in due


def test_a_deleted_file_runs_only_what_reads_every_file():
    assert due_tools(ALL, set(), {"src/old.py"}, full=False) == {"SONAR_SCAN": "all"}
    assert due_tools(ALL, set(), {"yarn.lock"}, full=False) == {**DEPENDENCY, "SONAR_SCAN": "all"}


def test_nothing_changed_runs_nothing_and_only_selected_tools_run():
    assert due_tools(ALL, set(), set(), full=False) == {}
    assert due_tools(["GITLEAKS", "SYFT"], {"package.json"}, set(), full=False) == {
        "GITLEAKS": "changed",
        "SYFT": "all",
    }


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("requirements.txt", True),
        ("a/b/pyproject.toml", True),
        ("Cargo.lock", True),
        ("uv.lock", True),
        ("app/build.gradle.kts", True),
        ("pubspec.lock", True),
        ("Pipfile", True),
        ("src/requirements.py", False),
        ("package.json.bak", False),
        ("notes/requirements.txt.md", False),
    ],
)
def test_is_manifest(path, expected):
    assert is_manifest(path) is expected


def test_changes_are_new_or_edited_files_and_deleted_ones():
    before = {"a.py": "1", "b.py": "2", "gone.py": "3"}

    assert changes({"a.py": "1", "b.py": "9", "new.py": "4"}, before) == (
        {"b.py", "new.py"},
        {"gone.py"},
    )
    assert changes({"a.py": "1"}, {}) == ({"a.py"}, set())


def test_a_file_a_failed_tool_missed_counts_as_changed_next_time():
    scanned = {"app.py": "1", "util.py": "2", "requirements.txt": "3"}
    changed = {"app.py", "requirements.txt"}
    due = {"SEMGREP": "changed", "TRIVY": "all", "SONAR_SCAN": "all"}

    assert baseline(scanned, changed, due, {"SEMGREP", "TRIVY"}) == scanned  # sonar: no findings
    assert baseline(scanned, changed, due, {"TRIVY"}) == {"util.py": "2"}
    assert baseline(scanned, changed, due, {"SEMGREP"}) == {"app.py": "1", "util.py": "2"}


def test_files_no_gitleaks_run_read_send_no_code_to_the_ai():
    scanned = {"app.py": "1", "util.py": "2"}
    changed = {"app.py"}
    due = {"SEMGREP": "changed", "GITLEAKS": "changed"}
    both = ["SEMGREP", "GITLEAKS"]

    assert unread_by_gitleaks(both, scanned, changed, due, {"SEMGREP", "GITLEAKS"}) == set()
    assert unread_by_gitleaks(both, scanned, changed, due, {"SEMGREP"}) == {"app.py"}
    assert unread_by_gitleaks(both, scanned, set(), {}, set()) == set()  # read before
    assert unread_by_gitleaks(["SEMGREP"], scanned, changed, due, {"SEMGREP"}) == set(scanned)


def test_under_matches_the_path_or_inside_it():
    assert _under("src/app.py", ["src"])
    assert _under("src", ["src"])
    assert not _under("srcx/app.py", ["src"])
    assert not _under(None, ["src"])


# ---------------------------------------------------------------------------
# Tools, paths and the auto scope
# ---------------------------------------------------------------------------

CODE_TARGET = "/workspace/code/abc"


def code_scope(**changes) -> ApprovedScope:
    fields = {"repo_paths": [CODE_TARGET], "allowed_tools": ALL, **changes}
    return ApprovedScope(assessment_id=uuid4(), **fields)


def test_scan_tools_are_the_asked_ones_or_the_scopes_in_a_fixed_order():
    scope = code_scope(allowed_tools=["SYFT", "SEMGREP", "NMAP"])

    assert scan_tools(scope, None) == ["SEMGREP", "SYFT"]
    assert scan_tools(scope, [ToolName.SONAR_SCAN, ToolName.SEMGREP]) == ["SEMGREP", "SONAR_SCAN"]
    with pytest.raises(ApiError) as error:
        scan_tools(code_scope(allowed_tools=["NMAP"]), None)
    assert error.value.code == "NO_CODE_TOOLS"


def test_only_a_scope_that_is_exactly_the_code_folder_is_reused():
    tools = list(CODE_TOOLS)

    assert is_code_folder_scope(code_scope(), CODE_TARGET, tools)
    assert not is_code_folder_scope(code_scope(allowed_tools=["SEMGREP"]), CODE_TARGET, tools)
    assert is_code_folder_scope(
        code_scope(allowed_tools=["SEMGREP"]), CODE_TARGET, [ToolName.SEMGREP]
    )
    assert not is_code_folder_scope(code_scope(repo_paths=["/workspace/code"]), CODE_TARGET, tools)
    assert not is_code_folder_scope(
        code_scope(excluded_targets=[f"{CODE_TARGET}/vendor"]), CODE_TARGET, tools
    )
    assert not is_code_folder_scope(code_scope(domains=["example.lab"]), CODE_TARGET, tools)


def test_scan_paths_are_checked_and_sorted_once():
    body = CodeScanIn(paths=["src", "api/app.py", "src"])

    assert body.paths == ["api/app.py", "src"]
    assert body.tools is None
    assert CodeScanIn(tools=["SEMGREP", "sonar_scan".upper()]).tools == [
        ToolName.SEMGREP,
        ToolName.SONAR_SCAN,
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"paths": ["../etc"]},
        {"paths": ["/etc/passwd"]},
        {"paths": ["a//b"]},
        {"paths": [""]},
        {"tools": ["NMAP"]},
        {"tools": []},
    ],
)
def test_bad_scan_paths_and_tools_are_refused(body):
    with pytest.raises(ValidationError):
        CodeScanIn(**body)
