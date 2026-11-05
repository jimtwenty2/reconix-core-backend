"""The template contract, and the start of the run every template shares.

A template is a kind of target (web URL, API, network, source code): it drafts the scope
for you to edit and approve, names the plan's phases and the methodology on the report.
It holds no findings, approvals or tool output: after you run the plan, everything comes
from the Core API (store/live.py), where the AI plans, the API checks every step and Kali
runs the tools.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ...models import (
    GATE_PLAN, GATE_SCOPE, GATE_TEMPLATE, ApprovalRequest, Finding, PlanTask, RunStep,
    ScopeManifest, Template,
)
from ...models.parser import ParsedTarget
from ..scenario import gate, log, say


@dataclass
class RunProfile:
    """What a template adds to the shared start of the run."""

    target_kind: str                        # "web application", "network range", …
    tools: List[str]
    plan: Tuple[Tuple[str, str], ...] = ()  # the plan's phases: (progress key, label)
    methodology: Tuple[str, ...] = ()       # standards followed (shown on the report)


@dataclass
class RunBundle:
    scope: ScopeManifest
    script: List[RunStep]
    approvals: List[ApprovalRequest]
    findings: List[Finding]
    login_2fa: bool = False
    plan: List[PlanTask] = None   # the named plan tasks, in order (set from the profile)
    methodology: List[str] = None   # standards followed (set from the profile)


# Every template's plan tracks the same five phases, named for its kind of target. The
# labels differ per template; the keys are the progress bars the run drives.
DEFAULT_PLAN: Tuple[Tuple[str, str], ...] = (
    ("discovery", "Discovery"),
    ("scanning", "Scanning"),
    ("validation", "Validate findings"),
    ("analysis", "Analyze & correlate"),
    ("report", "Generate report"),
)


def make_plan(pairs: Tuple[Tuple[str, str], ...],
              tools: Optional[Dict[str, Tuple[str, ...]]] = None) -> List[PlanTask]:
    """Build the ordered plan tasks (status starts pending; the run drives it).

    `tools`: phase key -> the scope tools that phase uses (none for a phase not listed).
    """
    tools = tools or {}
    return [PlanTask(key, label, tools=tools.get(key, ()))
            for key, label in (pairs or DEFAULT_PLAN)]


def build_plan(target_kind: str, ask_template: bool = True) -> List[RunStep]:
    """The first part of the run: identify the target and, if needed, ask for a template.

    It is built when the assessment starts. When the template is already known (the
    target left no doubt, or the operator picked it with /template) the rest of the run
    is appended at once; otherwise the operator picks (or changes) it at the gate and
    the rest is appended then. The Scope Manifest gate follows either way.
    """
    steps = [
        RunStep("parse", pause=0.8),
        log("AI", "Target parsed: $target"),
        say(f"Target identified: $target ({target_kind})."),
    ]
    if ask_template:
        steps += [say("Suggested template: $template. Opening templates…"), gate(GATE_TEMPLATE)]
    return steps


def build_rest(profile: RunProfile) -> List[RunStep]:
    """The run from the drafted scope to the moment the plan is sent to the Core API.

    Appended once the template is known. The rest of the run is the API's: each step the
    AI suggests, its check, your approval, the tool's output and the findings (live.py).
    """
    return [
        say("Template $picked: $template. Drafting a Scope Manifest…", tone="ok"),
        log("AI", "Scope Manifest drafted · pending approval", tone="warn", pause=1.0),
        say("Draft Scope Manifest ready. Testing stays paused until you approve it."),
        gate(GATE_SCOPE),
        say("Scope approved on the Core API. Assessment $assessment created.", tone="ok"),
        say("The AI drafts the test plan on the Core API. Review it, then run it; risky "
            "steps still ask you first.", pause=0.4),
        gate(GATE_PLAN),
        say("Plan sent to the Core API. Each step goes through its checks; Kali runs the "
            "tools.", tone="ok", pause=0.4),
        RunStep("phase", name="testing", pause=0.0),
    ]


def run_bundle(scope: ScopeManifest, profile: RunProfile,
               phase_tools: Optional[Dict[str, Tuple[str, ...]]] = None) -> RunBundle:
    """A template's bundle: its scope, the shared start of the run and its named plan."""
    return RunBundle(scope=scope, script=build_rest(profile), approvals=[], findings=[],
                     plan=make_plan(profile.plan, phase_tools),
                     methodology=list(profile.methodology))


# A template module exposes these three names.
class TemplateModule:   # documentation only; modules are duck-typed
    SPEC: Template
    def build_scope(self, parsed: ParsedTarget) -> ScopeManifest: ...
    def build_run(self, assessment) -> RunBundle: ...
