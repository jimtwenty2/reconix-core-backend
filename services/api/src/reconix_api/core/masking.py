"""Secret masking, as the API uses it.

The real function is reconix_ai.harness.mask_secrets (owner: Pojim). Until it is merged,
wiring.py puts a NOT_READY stub here, and tests use the fake in tests/fakes/fake_core.py.
"""

import json
import re
from collections.abc import Callable
from typing import Annotated, Any
from xml.etree.ElementTree import Element, ParseError, tostring

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring
from fastapi import Depends, Request

MaskSecrets = Callable[[str], tuple[str, int]]
"""Text -> (masked text, how many secrets were hidden)."""

PROBE = "x"  # a stand-in value, to ask the masker whether a key name is a secret's name
MIN_REPEATED = 6  # a secret this long or longer is also hidden where it repeats


def get_mask_secrets(request: Request) -> MaskSecrets:
    return request.app.state.mask_secrets


CurrentMask = Annotated[MaskSecrets, Depends(get_mask_secrets)]


# nmap -sV copies the scanned host's raw reply into its XML: the servicefp attribute and
# the fingerprint-strings script. nmap escapes it (\x20, \r\n, \"), which the masker
# cannot read through, so a cookie or password in it would be kept. No finding uses them:
# they are dropped before anything is saved.
RAW_REPLY_ATTRIBUTES = ("servicefp",)
RAW_REPLY_SCRIPTS = ("fingerprint-strings",)
RAW_REPLY_TEXT = [
    re.compile(r'\s+servicefp="[^"]*"?'),
    re.compile(r'<script id="fingerprint-strings".*?(?:/>|</script>|\Z)', re.DOTALL),
]


def mask_output(mask: MaskSecrets, text: str) -> tuple[str, int]:
    """Tool output, masked. JSON and XML are masked value by value, so the masking
    cannot break them and an escaped secret is still found."""
    masked = mask_json(mask, text)
    if masked is None:
        masked = mask_xml(mask, text)
    return masked if masked is not None else mask(drop_raw_replies(text))


def mask_xml(mask: MaskSecrets, text: str) -> tuple[str, int] | None:
    """XML (nmap -oX) -> masked XML: every attribute and text masked after the XML is
    read, so "&quot;" or "&#xa;" no longer hide a secret, and nmap's raw replies dropped.
    Not XML, or cut off: None."""
    if not text.lstrip().startswith("<"):
        return None
    try:
        root = fromstring(text)
    except (ParseError, DefusedXmlException):
        return None
    total = 0
    for node in root.iter():
        for script in [s for s in node.findall("script") if s.get("id") in RAW_REPLY_SCRIPTS]:
            node.remove(script)
        for name in RAW_REPLY_ATTRIBUTES:
            node.attrib.pop(name, None)
        total += _mask_node(mask, node)
    return tostring(root, encoding="unicode"), total


def _mask_node(mask: MaskSecrets, node: Element) -> int:
    total = 0
    for name, value in node.attrib.items():
        node.attrib[name], count = mask(value)
        total += count
    for part in ("text", "tail"):
        value = getattr(node, part)
        if value:
            masked, count = mask(value)
            setattr(node, part, masked)
            total += count
    return total


def drop_raw_replies(text: str) -> str:
    """The same raw replies, cut out of XML that could not be read (e.g. cut off)."""
    for pattern in RAW_REPLY_TEXT:
        text = pattern.sub("", text)
    return text


def mask_json(mask: MaskSecrets, text: str) -> tuple[str, int] | None:
    """JSON or JSON-lines text -> masked text that is still valid JSON. Not JSON: None.

    Masking the raw text would cut through escaped quotes (\\") and can leave a secret
    behind. Here each string is masked on its own, after the JSON is read.
    """
    try:
        value, count = _mask_value(mask, json.loads(text))
        return json.dumps(value), count
    except json.JSONDecodeError:
        pass
    rows = [line for line in text.splitlines() if line.strip()]
    if not rows:
        return None
    lines, total, read = [], 0, 0
    for number, row in enumerate(rows, start=1):
        try:
            value, count = _mask_value(mask, json.loads(row))
            row = json.dumps(value)
            read += 1
        except json.JSONDecodeError:
            if number < len(rows) or not read:
                return None  # not JSON lines
            row, count = mask(row)  # only the last line may be cut off
        lines.append(row)
        total += count
    return "\n".join(lines), total


def _mask_value(mask: MaskSecrets, value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return mask(value)
    if isinstance(value, list):
        items, total = [], 0
        for item in value:
            masked, count = _mask_value(mask, item)
            items.append(masked)
            total += count
        return items, total
    if isinstance(value, dict):
        return _mask_object(mask, value)
    return value, 0


def _mask_object(mask: MaskSecrets, value: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """A value under a secret's name is hidden whole, and also wherever it repeats in
    the object (gitleaks puts the secret in "Secret" and again in "Line" and "Match")."""
    secrets = {}
    for key, item in value.items():
        label = _secret_label(mask, key)
        if label and isinstance(item, str) and item and not item.startswith("[MASKED:"):
            secrets[item] = label
    masked, total = {}, 0
    for key, item in value.items():
        if isinstance(item, str) and item in secrets:
            masked[key], count = secrets[item], 1
        else:
            item, repeats = _hide_repeats(item, secrets)
            masked[key], count = _mask_value(mask, item)
            total += repeats
        total += count
    return masked, total


def _hide_repeats(item: Any, secrets: dict[str, str]) -> tuple[Any, int]:
    """Every repeat of a secret in item, also inside nested lists and objects."""
    if isinstance(item, str):
        total = 0
        for secret, label in secrets.items():
            # Short values ("x", "true") would match everywhere; only real secrets repeat.
            if len(secret) >= MIN_REPEATED and secret in item:
                item = item.replace(secret, label)
                total += 1
        return item, total
    if isinstance(item, list):
        pairs = [_hide_repeats(part, secrets) for part in item]
        return [part for part, _ in pairs], sum(count for _, count in pairs)
    if isinstance(item, dict):
        pairs = {key: _hide_repeats(part, secrets) for key, part in item.items()}
        return {key: part for key, (part, _) in pairs.items()}, sum(c for _, c in pairs.values())
    return item, 0


def _secret_label(mask: MaskSecrets, key: str) -> str | None:
    """e.g. "Secret" -> "[MASKED:token]"; "File" -> None. The masker decides, by name.
    Asked twice: as an assignment (Secret=...) and as an HTTP header (Set-Cookie: ...),
    since tools like ZAP put response headers in JSON keyed by the header's name."""
    for separator in ("=", ": "):
        probe = f"{key}{separator}{PROBE}"
        masked, count = mask(probe)
        if not count or masked == probe:
            continue
        prefix = f"{key}{separator}"
        return masked[len(prefix) :] if masked.startswith(prefix) else "[MASKED:secret]"
    return None
