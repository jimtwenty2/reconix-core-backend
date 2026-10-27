"""Secret masking.

Replaces passwords, tokens and API keys with a label such as [MASKED:password]
and counts how many it hid. This runs before anything is saved, shown, logged,
sent to the AI or stored in Qdrant.

Simple version (week 1): passwords and tokens in common shapes. The full
version (week 2) adds more secret types.
"""

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MaskRule:
    kind: str  # the label, e.g. "password" -> "[MASKED:password]"
    pattern: re.Pattern[str]
    # Mask only this named group and keep the rest (e.g. keep "password=").
    # None masks the whole match.
    group: str | None = None


def label(kind: str) -> str:
    return f"[MASKED:{kind}]"


# A value is quoted ("..." or '...'), or ends at whitespace, a quote, "&", "," or ";".
VALUE = r"""(?P<quote>["'])?(?P<secret>(?(quote)[^"']+|[^\s"'&,;]+))(?(quote)(?P=quote))"""

# Order matters: the specific shapes run first, so "Bearer eyJ..." is one token.
MASK_RULES = [
    MaskRule(
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    MaskRule(
        "token",
        re.compile(
            r"\b(?:Bearer|Basic|Token)\s+(?P<secret>[A-Za-z0-9._~+/=-]{8,})",
            re.IGNORECASE,
        ),
        "secret",
    ),
    MaskRule("token", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    MaskRule("token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    MaskRule("token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    MaskRule("api_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    MaskRule("api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    MaskRule("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    # user:password@host inside a URL
    MaskRule("password", re.compile(r"(?<=://)[^/\s:@]+:(?P<secret>[^/\s@]+)(?=@)"), "secret"),
    # password=..., "password": "...", PASSWORD: ...
    MaskRule(
        "password",
        re.compile(
            r"""\b(?:password|passwd|pwd|pass)["']?\s*[:=]\s*""" + VALUE,
            re.IGNORECASE,
        ),
        "secret",
    ),
    MaskRule(
        "api_key",
        re.compile(
            r"""\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret)["']?"""
            r"""\s*[:=]\s*""" + VALUE,
            re.IGNORECASE,
        ),
        "secret",
    ),
    MaskRule(
        "token",
        re.compile(
            r"""\b(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?id|secret)"""
            r"""["']?\s*[:=]\s*""" + VALUE,
            re.IGNORECASE,
        ),
        "secret",
    ),
]


def mask_secrets(text: str) -> tuple[str, int]:
    """Return the text with every secret replaced, and how many were replaced."""
    total = 0
    for rule in MASK_RULES:
        text, count = apply_rule(rule, text)
        total += count
    return text, total


def apply_rule(rule: MaskRule, text: str) -> tuple[str, int]:
    count = 0

    def swap(match: re.Match[str]) -> str:
        nonlocal count
        if rule.group is None:
            count += 1
            return label(rule.kind)
        if match.group(rule.group).startswith("[MASKED:"):
            return match.group(0)  # already masked by an earlier rule
        count += 1
        # Keep the text around the secret, e.g. the "password=" in front of it.
        start = match.start(rule.group) - match.start()
        end = match.end(rule.group) - match.start()
        whole = match.group(0)
        return whole[:start] + label(rule.kind) + whole[end:]

    return rule.pattern.sub(swap, text), count


def mask_value(value: Any) -> tuple[Any, int]:
    """Mask every string inside a value (str, dict, list or tuple), for audit details."""
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, dict):
        masked, total = {}, 0
        for key, item in value.items():
            masked[key], count = mask_value(item)
            total += count
        return masked, total
    if isinstance(value, list | tuple):
        items, total = [], 0
        for item in value:
            masked_item, count = mask_value(item)
            items.append(masked_item)
            total += count
        return type(value)(items), total
    return value, 0
