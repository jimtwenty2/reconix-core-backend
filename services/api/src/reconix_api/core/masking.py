"""Secret masking, as the API uses it.

The real function is reconix_ai.harness.mask_secrets (owner: Pojim). Until it is merged,
wiring.py puts a NOT_READY stub here, and tests use the fake in tests/fakes/fake_core.py.
"""

import json
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, Request

MaskSecrets = Callable[[str], tuple[str, int]]
"""Text -> (masked text, how many secrets were hidden)."""

PROBE = "x"  # a stand-in value, to ask the masker whether a key name is a secret's name
MIN_REPEATED = 6  # a secret this long or longer is also hidden where it repeats


def get_mask_secrets(request: Request) -> MaskSecrets:
    return request.app.state.mask_secrets


CurrentMask = Annotated[MaskSecrets, Depends(get_mask_secrets)]


def mask_output(mask: MaskSecrets, text: str) -> tuple[str, int]:
    """Tool output, masked. JSON is masked value by value, so the masking cannot break it."""
    masked = mask_json(mask, text)
    return masked if masked is not None else mask(text)


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
            for secret, label in secrets.items():
                # Short values ("x", "true") would match everywhere; only real secrets repeat.
                if isinstance(item, str) and len(secret) >= MIN_REPEATED and secret in item:
                    item = item.replace(secret, label)
                    total += 1
            masked[key], count = _mask_value(mask, item)
        total += count
    return masked, total


def _secret_label(mask: MaskSecrets, key: str) -> str | None:
    """e.g. "Secret" -> "[MASKED:token]"; "File" -> None. The masker decides, by name."""
    probe = f"{key}={PROBE}"
    masked, count = mask(probe)
    if not count or masked == probe:
        return None
    prefix = f"{key}="
    return masked[len(prefix) :] if masked.startswith(prefix) else "[MASKED:secret]"
