from dataclasses import asdict, fields

from reconix_ai.contracts import (
    AgentAnswer,
    ChatMessage,
    FindingAnalysis,
    FindingInput,
    ProposedAction,
    ResumeInput,
    ToolRunInput,
)

# Columns of findings in ERD V3 that the agent may read.
FINDING_COLUMNS = {
    "code",
    "title",
    "target",
    "description",
    "severity_status",
    "finding_status",
    "cvss_score",
    "cwe_ids",
    "owasp_id",
    "cve_ids",
}
# Columns of findings the analysis may suggest a value for.
SUGGESTED_COLUMNS = {
    "severity_status",
    "cvss_score",
    "cwe_ids",
    "owasp_id",
    "cve_ids",
    "impact",
    "remediation",
}
# The fields of the proposed shared AgentResponse. Keep in step with the proposal.
AGENT_RESPONSE_FIELDS = {
    "text",
    "plan",
    "proposed_action",
    "risk",
    "blocked",
    "references",
    "reflections",
    "analysis_summary",
    "analysis",
    "validation_status",
    "validation_reason",
    "executive_summary",
    "methodology",
    "agent_run_id",
    "checkpoint_id",
    "waiting",
    "decision",
    "prompt_tokens",
    "completion_tokens",
    "masked_count",
}


def names(shape: type) -> set[str]:
    return {item.name for item in fields(shape)}


def test_finding_input_uses_the_erd_columns() -> None:
    # confidence is a derived trust tier (never an ERD column), carried for the report.
    assert names(FindingInput) == FINDING_COLUMNS | {"confidence"}


def test_analysis_never_suggests_a_parser_owned_column() -> None:
    parser_owned = {"title", "target", "description", "finding_status"}

    assert SUGGESTED_COLUMNS <= names(FindingAnalysis)
    assert not parser_owned & names(FindingAnalysis)


def test_chat_message_uses_the_erd_columns() -> None:
    assert names(ChatMessage) == {"role", "content_masked"}


def test_tool_run_carries_its_status_and_approval() -> None:
    assert {"risk_level", "tool_run_status", "approval_check"} <= names(ToolRunInput)


def test_resume_names_the_run_the_assessment_and_the_action() -> None:
    assert names(ResumeInput) == {
        "agent_run_id",
        "assessment_id",
        "approval_id",
        "action",
        "decision",
    }


def test_next_step_cannot_choose_a_finding() -> None:
    assert "finding_id" not in names(ProposedAction)


def test_answer_has_exactly_the_agent_response_fields() -> None:
    answer = asdict(AgentAnswer(text="Start with a service scan.", agent_run_id="run-1"))

    assert set(answer) == AGENT_RESPONSE_FIELDS


def test_a_plan_answer_has_no_analysis_or_report() -> None:
    answer = AgentAnswer(text="Start with a service scan.")

    assert answer.analysis == [] and answer.analysis_summary == ""
    assert answer.executive_summary is None and answer.methodology is None
