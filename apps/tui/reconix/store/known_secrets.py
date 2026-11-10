"""The secrets Reconix itself holds, so `redact()` can mask them by their value.

The shapes in `redact.py` miss a secret that looks like any other word: the test account's
password or the session cookie the operator gave at the target login (`vault.py`), or a model
API key entered with /provider ("sk-mock-0000-1234" is too short for the sk- shape). Whatever
text is masked (chat, history, activity, feedback, saved files, what a model is sent) is
masked for these values as well.

A provider's API key is kept by the Core API, not on this computer; this module remembers,
in memory only for this app run, the keys you typed into /provider so a key typed again in a
chat line is still masked. Nothing here is logged, printed or saved.

`values()` returns them longest first (a longer value is masked before a shorter one inside
it), only those of `MIN_LENGTH` characters or more (a shorter one would mask ordinary words).
"""

from typing import Dict, List, Set

from . import lists

MIN_LENGTH = 4

# provider id -> the API keys typed for it this app run (replaced when the key changes).
_ENTERED_KEYS: Dict[str, Set[str]] = {}


def set_keys(provider_id: str, keys: Set[str]) -> None:
    """Remember the keys typed for a provider (replacing any it had), so they stay masked."""
    kept = {k for k in keys if k}
    if kept:
        _ENTERED_KEYS[provider_id] = kept
    else:
        _ENTERED_KEYS.pop(provider_id, None)


def forget_provider(provider_id: str) -> None:
    _ENTERED_KEYS.pop(provider_id, None)


def reset() -> None:
    _ENTERED_KEYS.clear()


def _login_values() -> Set[str]:
    """The cookie or password every assessment of this session holds for its target login."""
    found: Set[str] = set()
    for assessment in lists.ASSESSMENTS:
        for entry in assessment.vault:
            value = entry.secret.reveal() if entry.secret else ""
            found.add(value)
            found.add(value.strip())
    return found


def _provider_values() -> Set[str]:
    """Every provider API key typed this app run."""
    found: Set[str] = set()
    for keys in _ENTERED_KEYS.values():
        found.update(keys)
    return found


def values() -> List[str]:
    """Every secret Reconix holds, `MIN_LENGTH` characters or more, longest first."""
    found = _login_values()
    found.update(_provider_values())
    return sorted((v for v in found if len(v) >= MIN_LENGTH), key=len, reverse=True)
