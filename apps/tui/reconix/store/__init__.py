"""In-memory data store — the only thing screens import for data.

Every function here reads or writes the shared lists in `lists.py`. To move to
the Reconix backend later, keep these function names and signatures and change
their bodies to call the API; the screens do not need to change.
"""

from .activity import (
    add_feedback, current_events, current_feedback, current_operator, list_events,
    list_feedback, log_event,
)
from .api_form import save_api_form
from .approvals import (
    approvals_count, approve, can_edit, decision_for, decline_confirmation, edit_approval,
    get_approval, is_approved, list_approval_decisions, needs_confirmation, reject,
    request_confirmation,
)
from .assessment import (
    MAX_REQUEST_LENGTH, AssessmentCard, add_request, assessment_label, assessment_status,
    get_assessment, is_empty_assessment, list_assessments, list_requests, recorded_line,
    switch_assessment,
)
from .errors import StoreValidationError
from .findings import (
    SEVERITY_ORDER, TRIAGE_LABELS, TRIAGE_STATUS, confirmed_count, findings_line, get_finding,
    list_findings, review_count, triage_finding,
)
from .findings_view import (
    FINDING_FILTERS, FINDING_SORTS, filter_counts, filter_label, find_findings, key_findings,
    severity_counts, sort_label,
)
from .history import add_history, list_history
from .llm_chat import (
    Draft, begin_reply, build_draft, drop_pending_replies, preview_reply, record_draft,
)
from . import knowledge
from .knowledge import add_source, list_sources, remove_source
from .knowledge import clear as clear_knowledge
from .knowledge import search as search_knowledge
from .openapi import (
    api_schema_chat_block, api_schema_endpoint, api_schema_handoff, api_spec_handoff,
    api_spec_methods_outside, attach_api_spec, can_attach_api_spec, get_api_spec,
    remove_api_spec,
)
from .persist import autosave, close_session, web_dashboard_url
from .ai_plan import (
    apply_plan_draft, fetch_plan_draft, plan_author, plan_draft_failed, plan_draft_request,
    plan_drafting,
)
from .live import Job as LiveJob
from .live import failed_reason as live_failed
from .live import next_job as next_live_job
from .live import retry as retry_live
from .plan import gated_count, plan_overview, rejected_checks, validation_skipped
from .plan_order import answer_plan_reorder, reorder_gated, wants_plan_reorder
from .plan_order import movable as movable_checks
from .providers import (
    activate, active_llm_settings, active_model, active_remote_label,
    core_api_approve, core_api_needs_ok, get_provider, list_providers, set_provider,
    test_provider, unset_provider,
)
from .progress import StepStatus, step_states, step_status
from .report import (
    assessment_summary, generate_report, list_report_formats, list_report_sections,
    report_data,
)
from .retest import compare_findings, previous_assessment, retest, severity_trend
from .run import (
    advance, counters, display_phase, elapsed, gate_state, get_run, is_completed, is_finished,
    is_plan_started, llm_answer, login_refusal, new_assessment, peek, phase_progress,
    pipeline_stage, plan_tasks, reject_scope, run_plan, say_operator_line, say_to_assistant,
    approve_more_time, start_run, stop_for_time, stop_run, submit_prompt, time_limit,
    waiting_gate,
)
from .scope import (
    approve_scope, blocked_count, check_request, edit_scope, get_scope, is_scope_approved,
    list_verdicts, reopen_scope, scope_changeable, scope_editable, time_limit_pending,
)
from .scope_ask import (
    ScopeChoices, answer_scope_change, scope_tick_choices, wants_scope_change,
)
from .scope_suggest import (
    apply_scope_suggest, fetch_scope_suggest, scope_suggest_failed, scope_suggest_request,
    scope_reading, scope_suggesting, scope_suggest_waiting, suggested_tools,
    suggested_tool_notes,
)
from .scope_view import describe_scope
from .seed import load_demo_data
from .step_intent import (
    asks_about_decision, decision_reply, view_reply, wants_decision, wants_plan_change,
    wants_view,
)
from .step_text import approval_text, plan_text, scope_text, template_text
from .targets import (
    DASH_RANGE_UNSUPPORTED, TargetCheck, check_target, looks_like_target, validate_target,
)
from .templates import get_template, list_templates, select_template, selected_template
from .templates.techniques import grouped as technique_groups
from .thinking import block_seconds, group_stream, stream
from .transcript import last_exchange, list_activity, list_chat
from .tools import tool_login, tools_login
from .vault import (
    code_needed, current_auth_challenge, has_test_account, is_authenticated, is_code_verified,
    login_done, login_kind, login_tools, provide_auth, vault_scope,
)

load_demo_data()

reset = load_demo_data   # tests: restore the demo rows between runs

__all__ = [
    "StoreValidationError", "reset", "MAX_REQUEST_LENGTH",
    # assessment and requests
    "get_assessment", "assessment_label", "list_requests", "add_request", "recorded_line",
    "list_assessments", "switch_assessment", "assessment_status", "AssessmentCard",
    "is_empty_assessment",
    # the run
    "submit_prompt", "start_run", "check_target", "say_to_assistant", "say_operator_line",
    "login_refusal",
    "TargetCheck", "looks_like_target", "validate_target", "DASH_RANGE_UNSUPPORTED",
    "llm_answer", "new_assessment",
    "advance", "peek", "gate_state", "stop_run",
    "waiting_gate", "get_run", "display_phase", "time_limit_pending",
    "approve_more_time", "stop_for_time", "is_completed", "is_finished", "counters",
    "phase_progress", "plan_tasks", "plan_overview", "gated_count", "step_states",
    # the plan, drafted by the AI on the Core API (store/ai_plan.py)
    "plan_draft_request", "fetch_plan_draft", "apply_plan_draft", "plan_draft_failed",
    "plan_drafting", "plan_author",
    # the run on the Core API (store/live.py): its next call, made in a worker
    "LiveJob", "next_live_job", "live_failed", "retry_live",
    "rejected_checks", "validation_skipped",
    "pipeline_stage", "elapsed", "time_limit",
    # gates
    "list_templates", "get_template", "select_template", "selected_template",
    "get_scope", "approve_scope", "edit_scope", "is_scope_approved", "reject_scope",
    "describe_scope", "check_request", "run_plan", "is_plan_started",
    "list_verdicts", "blocked_count", "scope_editable",
    # the chat inside a step ("Chat about this"): its content as text, scope change asks
    "scope_text", "plan_text", "approval_text", "template_text",
    "wants_scope_change", "answer_scope_change", "ScopeChoices", "reopen_scope",
    "scope_tick_choices", "scope_suggest_request", "fetch_scope_suggest",
    "apply_scope_suggest", "scope_suggest_failed", "scope_suggesting",
    "suggested_tools", "scope_reading", "suggested_tool_notes", "scope_suggest_waiting",
    "scope_changeable", "wants_plan_change", "technique_groups",
    "wants_decision", "asks_about_decision", "wants_view", "decision_reply", "view_reply",
    "wants_plan_reorder", "answer_plan_reorder", "reorder_gated", "movable_checks",
    "step_status", "StepStatus",
    "provide_auth", "current_auth_challenge", "has_test_account",
    "is_authenticated", "is_code_verified", "vault_scope",
    "login_kind", "login_tools", "login_done", "code_needed", "tool_login", "tools_login",
    "get_approval", "needs_confirmation", "request_confirmation", "decline_confirmation",
    "approve", "reject", "is_approved", "decision_for", "list_approval_decisions",
    "approvals_count", "can_edit", "edit_approval",
    # results
    "list_findings", "get_finding", "confirmed_count", "review_count",
    "findings_line", "SEVERITY_ORDER",
    "triage_finding", "TRIAGE_STATUS", "TRIAGE_LABELS",
    "FINDING_FILTERS", "FINDING_SORTS", "find_findings", "filter_counts", "filter_label",
    "sort_label", "severity_counts", "key_findings",
    "list_report_formats", "list_report_sections", "report_data", "generate_report",
    "assessment_summary",
    "retest", "severity_trend", "compare_findings", "previous_assessment",
    # transcript, audit, history
    "list_chat", "last_exchange", "list_activity",
    "stream", "group_stream", "block_seconds",
    "current_operator", "log_event", "list_events", "add_feedback", "list_feedback",
    "current_events", "current_feedback",
    "add_history", "list_history",
    # flexible LLM: providers and the active model
    "list_providers", "get_provider", "set_provider", "unset_provider", "test_provider",
    "activate", "active_model", "active_llm_settings", "active_remote_label",
    "core_api_approve", "core_api_needs_ok",
    "Draft", "build_draft", "record_draft", "begin_reply", "preview_reply",
    "drop_pending_replies",
    # the saved copy the web dashboard reads
    "autosave", "close_session", "web_dashboard_url",
    # the API template's OpenAPI spec
    "attach_api_spec", "remove_api_spec", "get_api_spec", "can_attach_api_spec", "save_api_form",
    "api_spec_handoff", "api_spec_methods_outside",
    "api_schema_handoff", "api_schema_chat_block", "api_schema_endpoint",
    # knowledge add-ons (/add-on): reference files for the AI
    "knowledge", "add_source", "list_sources", "remove_source",
    "clear_knowledge", "search_knowledge",
]
