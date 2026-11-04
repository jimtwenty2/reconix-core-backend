from uuid import uuid4

import pytest

from reconix_api.schemas.vscode_chat import (
    ExplainFindingArgs,
    FunctionName,
    ListFindingsArgs,
    NoArgs,
    ProposeFixArgs,
    RunsOn,
    StartScanArgs,
)
from reconix_api.services.chat_functions import (
    FUNCTIONS,
    FunctionContext,
    FunctionError,
    explain_finding,
    list_findings,
    propose_fix,
    spec,
    start_scan,
    summarize_findings,
)
from tests.unit.services.test_chat_chooser import FINDINGS, LEAK, NOISE, SQL, XSS


def context(findings=FINDINGS) -> FunctionContext:
    """Enough for the functions that only read the findings: no database is touched."""
    return FunctionContext(None, None, None, None, None, uuid4(), lambda: list(findings))


def test_every_function_has_a_spec_a_model_can_read():
    for function in FUNCTIONS.values():
        described = spec(function)
        assert described.description.endswith(".")
        assert described.parameters["type"] == "object"


def test_only_client_functions_ask_first():
    for function in FUNCTIONS.values():
        assert function.confirm == (function.runs_on == RunsOn.CLIENT)
    client = {name for name, f in FUNCTIONS.items() if f.runs_on == RunsOn.CLIENT}
    assert client == {
        FunctionName.CANCEL_SCAN,
        FunctionName.START_SCAN,
        FunctionName.PROPOSE_FIX,
        FunctionName.SWITCH_MODEL,
    }


def test_list_filters_by_severity_and_file():
    outcome = list_findings(
        context(), ListFindingsArgs(severity="HIGH", path="src/routes/users.js")
    )
    assert outcome.result.findings == [LEAK]
    assert outcome.text == "1 finding."


def test_explain_refuses_a_finding_of_another_scan():
    assert (
        explain_finding(context(), ExplainFindingArgs(finding_id=XSS.finding_id)).result.finding
        == XSS
    )
    with pytest.raises(FunctionError):
        explain_finding(context(), ExplainFindingArgs(finding_id=uuid4()))


def test_summary_counts_open_findings_only_and_puts_the_worst_first():
    summary = summarize_findings(context(), NoArgs()).result
    assert summary.total == 3  # NOISE is a false positive
    assert (summary.counts["CRITICAL"], summary.counts["HIGH"]) == (1, 2)
    assert summary.files[0].path == "src/routes/users.js"
    assert summary.fix_first == [SQL.finding_id, XSS.finding_id, LEAK.finding_id]


def test_fix_keeps_only_this_sessions_findings():
    outcome = propose_fix(
        context(), ProposeFixArgs(finding_ids=[uuid4(), XSS.finding_id, XSS.finding_id])
    )
    assert outcome.arguments.finding_ids == [XSS.finding_id]
    assert propose_fix(context(), ProposeFixArgs(finding_ids=[uuid4()])).arguments is None
    assert propose_fix(context([]), ProposeFixArgs()).arguments is None


def test_fix_may_name_a_false_positive_on_purpose():
    outcome = propose_fix(context(), ProposeFixArgs(finding_ids=[NOISE.finding_id]))
    assert outcome.arguments.finding_ids == [NOISE.finding_id]


@pytest.mark.parametrize("path", ["../secrets", "/etc", "a//b", "src/../x"])
def test_paths_outside_the_workspace_are_refused(path):
    with pytest.raises(FunctionError):
        start_scan(context(), StartScanArgs(paths=[path]))
    with pytest.raises(FunctionError):
        list_findings(context(), ListFindingsArgs(path=path))


def test_a_list_path_has_a_length_limit():
    with pytest.raises(ValueError):
        ListFindingsArgs(path="a" * 2000)


def test_unknown_arguments_are_refused():
    with pytest.raises(ValueError):
        StartScanArgs.model_validate({"full": True, "target": "/"})
