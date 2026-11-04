"""Fakes for get_operator, check, get_approved_scope and write_audit."""

import ipaddress
import posixpath
import re
from pathlib import PurePosixPath
from uuid import NAMESPACE_URL, UUID, uuid5

from reconix_api.core.interfaces import (
    RISK_ORDER,
    Action,
    ApprovedScope,
    AuditEvent,
    CheckContext,
    CheckName,
    CheckResult,
    Decision,
    Operator,
    RiskLevel,
    ToolName,
)

OPERATOR_TOKEN = "fake-operator-token"

# A rough copy of the real risk table, good enough for tests.
FAKE_RISK = {
    ToolName.NMAP: RiskLevel.LOW,
    ToolName.SEMGREP: RiskLevel.LOW,
    ToolName.GITLEAKS: RiskLevel.LOW,
    ToolName.NUCLEI: RiskLevel.MEDIUM,
    ToolName.ZAP: RiskLevel.HIGH,
}
SHELL_CHARACTERS = set(";|&$`<>\n")


class FakeOperators:
    def __init__(self) -> None:
        self.tokens = {
            OPERATOR_TOKEN: Operator(session_id=uuid5(NAMESPACE_URL, "operator"), actor="operator"),
        }

    def get_operator(self, token: str) -> Operator:
        if token not in self.tokens:
            raise PermissionError("UNKNOWN_TOKEN")
        return self.tokens[token]


class FakeScopes:
    def __init__(self) -> None:
        self.scopes: dict[UUID, ApprovedScope] = {}

    def add(self, scope: ApprovedScope) -> None:
        self.scopes[scope.assessment_id] = scope

    def get_approved_scope(self, assessment_id: UUID) -> ApprovedScope:
        if assessment_id not in self.scopes:
            raise LookupError("SCOPE_NOT_APPROVED")
        return self.scopes[assessment_id]


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write_audit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _blocked(check: CheckName, reason: str, risk: RiskLevel = RiskLevel.HIGH) -> CheckResult:
    return CheckResult(decision=Decision.BLOCKED, risk=risk, blocked_by=check, reason=reason)


def _in_scope(target: str, scope: ApprovedScope) -> bool:
    if target in scope.excluded_targets:
        return False
    try:
        address = ipaddress.ip_address(target)
        return any(address in ipaddress.ip_network(r, strict=False) for r in scope.ip_ranges)
    except ValueError:
        pass
    if target in scope.domains:
        return True
    if any(target.startswith(prefix) for prefix in scope.url_prefixes):
        return True
    # Like the real check: a path is in scope only inside a whole scoped folder, so
    # "/workspace/code/a-x" is not inside "/workspace/code/a".
    path = PurePosixPath(posixpath.normpath(target))
    return target.startswith("/") and any(
        path.is_relative_to(folder) for folder in scope.repo_paths
    )


def fake_check(action: Action, context: CheckContext) -> CheckResult:
    """A small version of the real pipeline: input, scope, command, risk. No loop check."""
    if context.input_text is not None and len(context.input_text) > 4000:
        return _blocked(CheckName.INPUT, "INPUT_TOO_LONG")
    if ".." in action.target or not _in_scope(action.target, context.scope):
        return _blocked(CheckName.SCOPE, "TARGET_OUT_OF_SCOPE")
    if action.tool.upper() not in {tool.upper() for tool in context.scope.allowed_tools}:
        return _blocked(CheckName.SCOPE, "TOOL_NOT_ALLOWED")
    if any(SHELL_CHARACTERS & set(argument) for argument in action.arguments):
        return _blocked(CheckName.COMMAND, "SHELL_CHARACTERS")

    risk = FAKE_RISK.get(action.tool.upper(), RiskLevel.HIGH)  # other catalog tools: HIGH
    if action.is_validation and RISK_ORDER[risk] < RISK_ORDER[RiskLevel.MEDIUM]:
        risk = RiskLevel.MEDIUM
    if RISK_ORDER[risk] > RISK_ORDER[context.scope.max_risk]:
        return _blocked(CheckName.RISK, "RISK_ABOVE_SCOPE_MAX", risk)
    return CheckResult(decision=Decision.ALLOW, risk=risk)


SECRET_SHAPE = re.compile(r"(?i)((?:password|token|api[_-]?key)\s*[:=]\s*)(\S+)")


def fake_mask_secrets(text: str) -> tuple[str, int]:
    """A small version of the real masking: only key=value secrets."""
    return SECRET_SHAPE.subn(r"\1[MASKED:secret]", text)
