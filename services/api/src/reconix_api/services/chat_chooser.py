"""Chooses the chat function a VS Code chat message asks for, with fixed keyword rules.

Only short, clear commands are chosen ("scan this project", "fix all high findings",
"stop"); anything else is a question for the agent. A model may choose later instead;
whatever chooses, chat_functions checks the call the same way.

The patterns that choose a function are anchored at the start of the message, so a
command word in the middle of a question ("a summary of this design") chooses nothing.
Only messages up to MAX_COMMAND_CHARS are matched, so no message can make the matching
slow. Findings and providers are loaded only when a rule needs them.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from reconix_api.models.enums import FindingStatus, SeverityStatus
from reconix_api.schemas.code import CodeFindingOut
from reconix_api.schemas.vscode_chat import FunctionCall, FunctionName
from reconix_api.services.chat_functions import SEVERITY_ORDER

MAX_COMMAND_CHARS = 300


@dataclass(frozen=True)
class ProviderWords:
    llm_provider_id: UUID
    words: frozenset[str]  # of its display name, model name and type, lower case


CANCEL = re.compile(r"^(stop|cancel|abort)(\s+(the\s+)?(scan|scanning|it))?[.!]?$", re.I)
SCAN_STATUS = re.compile(
    r"^((what is|what's) the\s+)?scan\s+(status|progress)\??$"
    r"|^is the scan\s+(done|finished|over|running|still running)\??$",
    re.I,
)
FIX = re.compile(r"^(please\s+|can you\s+|could you\s+)?(fix|repair|patch|remediate)\b", re.I)
SUMMARIZE = re.compile(
    r"^(please\s+)?(summari[sz]e|summary|overview)"
    r"(\s+(of\s+)?(the\s+|all\s+)?(findings|results|scan))?[.!]?$",
    re.I,
)
EXPLAIN = re.compile(r"^(explain|describe|tell me about|what is|what's)\b", re.I)
LIST = re.compile(r"^(show|list|view|open)\b.*\b(findings|results|problems|issues)\b", re.I)
SWITCH = re.compile(r"^(switch|change|use|set|select)\s+(?:(?:to|the|model|llm)\s+)*(\S.*)$", re.I)
MODEL_WORDS = re.compile(
    r"\b(model|llm|gpt|openai|ollama|qwen|reconix|claude|anthropic|deepseek)\b", re.I
)
QUESTION = re.compile(
    r"^(what|why|how|which|where|when|who|is|are|was|does|do|did|should|can|could)\b", re.I
)
RESCAN = re.compile(r"^re-?scan\b", re.I)
SCAN = re.compile(r"^(please\s+|can you\s+|could you\s+)?(scan|analy[sz]e)\b", re.I)
SCAN_VERB = re.compile(r"\b(scan|analy[sz]e)\b", re.I)
# What a whole-workspace scan names; "analyze this function" names none of these.
SCAN_OBJECT = re.compile(
    r"\b(project|workspace|folder|repo|repository|codebase|source code|everything|again|it)\b", re.I
)
FULL = re.compile(r"\bfrom scratch\b|\bfull\b|\beverything again\b|\ball files\b", re.I)
ABOUT_FINDINGS = re.compile(r"\b(finding|findings|result|results)\b", re.I)
FINDING_REF = re.compile(
    r"\b[A-Z]{2,10}-\d{3,}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)
ALL = re.compile(r"\b(all|every|everything)\b", re.I)
NOT_MODEL_WORDS = {"model", "llm", "the", "to"}

SEVERITY_WORDS = {
    "critical": SeverityStatus.CRITICAL,
    "crit": SeverityStatus.CRITICAL,
    "high": SeverityStatus.HIGH,
    "medium": SeverityStatus.MEDIUM,
    "med": SeverityStatus.MEDIUM,
    "low": SeverityStatus.LOW,
    "unknown": SeverityStatus.UNKNOWN,
    "info": SeverityStatus.NONE,
    "informational": SeverityStatus.NONE,
}


def choose(
    text: str,
    load_findings: Callable[[], list[CodeFindingOut]],
    load_providers: Callable[[], list[ProviderWords]],
) -> FunctionCall | None:
    """The function a short, clear command asks for, or None. Checked in order."""
    if len(text) > MAX_COMMAND_CHARS:
        return None
    text = text.strip()
    if not text:
        return None
    if CANCEL.match(text):
        return FunctionCall(name=FunctionName.CANCEL_SCAN)
    if SCAN_STATUS.match(text):
        return FunctionCall(name=FunctionName.SCAN_STATUS)
    if FIX.match(text):
        ids = [str(finding.finding_id) for finding in fix_targets(text, load_findings())]
        return FunctionCall(name=FunctionName.PROPOSE_FIX, arguments={"finding_ids": ids})
    if SUMMARIZE.match(text):
        return FunctionCall(name=FunctionName.SUMMARIZE_FINDINGS)
    named = []
    if EXPLAIN.match(text) and FINDING_REF.search(text):
        named = findings_named(text, load_findings())
    if len(named) == 1:
        arguments = {"finding_id": str(named[0].finding_id)}
        return FunctionCall(name=FunctionName.EXPLAIN_FINDING, arguments=arguments)
    if LIST.match(text):
        arguments = list_filter(text, load_findings())
        return FunctionCall(name=FunctionName.LIST_FINDINGS, arguments=arguments)
    switched = SWITCH.match(text)
    if switched and MODEL_WORDS.search(text):
        provider = match_provider(switched.group(2).rstrip(".!?"), load_providers())
        if provider is None:
            return None  # the agent can say which models there are
        arguments = {"llm_provider_id": str(provider.llm_provider_id)}
        return FunctionCall(name=FunctionName.SWITCH_MODEL, arguments=arguments)
    # "what did the scan find?" and "check this finding" are questions, not scans.
    if QUESTION.match(text):
        return None
    if "://" in text:
        return None  # a link names something else to scan; only the agent can say what
    if RESCAN.match(text):
        return FunctionCall(name=FunctionName.START_SCAN)
    if ABOUT_FINDINGS.search(text) or FINDING_REF.search(text):
        return None
    if SCAN.match(text) and SCAN_OBJECT.search(text):
        arguments = {"full": True} if FULL.search(text) else {}
        return FunctionCall(name=FunctionName.START_SCAN, arguments=arguments)
    if SCAN_VERB.search(text) and SCAN_OBJECT.search(text):
        arguments = {"full": True} if FULL.search(text) else {}
        return FunctionCall(name=FunctionName.START_SCAN, arguments=arguments)
    return None


def findings_named(text: str, findings: list[CodeFindingOut]) -> list[CodeFindingOut]:
    """Findings the message names by code or id, in the order named."""
    named: list[CodeFindingOut] = []
    for ref in FINDING_REF.findall(text):
        for finding in findings:
            hit = ref.upper() == finding.code.upper() or ref.lower() == str(finding.finding_id)
            if hit and finding not in named:
                named.append(finding)
    return named


def fix_targets(text: str, findings: list[CodeFindingOut]) -> list[CodeFindingOut]:
    """Findings named by code or id first. Else the open findings of the severities and
    files the message names, or every open one for "all". Most serious first. Empty
    when the message names nothing."""
    named = findings_named(text, findings)
    if named:
        return named
    severities = severities_in(text)
    paths = paths_in(text, findings)
    if not severities and not paths and not ALL.search(text):
        return []
    picked = [
        finding
        for finding in findings
        if finding.finding_status == FindingStatus.OPEN
        and (not severities or finding.severity_status in severities)
        and (not paths or finding.path in paths)
    ]
    return sorted(
        picked, key=lambda f: (SEVERITY_ORDER.index(f.severity_status), f.path or "", f.code)
    )


def list_filter(text: str, findings: list[CodeFindingOut]) -> dict[str, str]:
    """The severity and the file to list, when the message names exactly one of each."""
    arguments = {}
    severities = severities_in(text)
    if len(severities) == 1:
        arguments["severity"] = str(next(iter(severities)))
    paths = paths_in(text, findings)
    if len(paths) == 1:
        arguments["path"] = next(iter(paths))
    return arguments


def severities_in(text: str) -> set[SeverityStatus]:
    words = re.findall(r"[a-z]+", text.lower())
    return {SEVERITY_WORDS[word] for word in words if word in SEVERITY_WORDS}


def paths_in(text: str, findings: list[CodeFindingOut]) -> set[str]:
    """Paths of findings whose path, or file name longer than three characters, is in
    the message."""
    tokens = set(re.findall(r"[\w./-]+", text))
    paths = set()
    for finding in findings:
        if finding.path is None:
            continue
        name = finding.path.rsplit("/", 1)[-1]
        if finding.path in tokens or (len(name) > 3 and name in tokens):
            paths.add(finding.path)
    return paths


def provider_words(display_name: str, model_name: str, provider_type: str) -> frozenset[str]:
    return frozenset(
        re.findall(r"[a-z0-9][a-z0-9.\-]*", f"{display_name} {model_name} {provider_type}".lower())
    )


def match_provider(query: str, providers: list[ProviderWords]) -> ProviderWords | None:
    """The first provider with every word of the query, else the first with any word.
    Whole words only, so "a" does not match every provider."""
    words = [
        w for w in re.findall(r"[a-z0-9][a-z0-9.\-]*", query.lower()) if w not in NOT_MODEL_WORDS
    ]
    if not words:
        return None
    for provider in providers:
        if all(word in provider.words for word in words):
            return provider
    for provider in providers:
        if any(word in provider.words for word in words):
            return provider
    return None
