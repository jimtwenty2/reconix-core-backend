"""Showing hidden values (disclosure).

Masking hides each secret behind a label such as [MASKED:password]. This file keeps
the real values, encrypted, in a protected folder, so a person can see one of them
later with a `disclosure` approval. The API uses it like this:

    masked, count, hidden = mask_and_keep(tool_output)
    vault.keep(evidence_id, hidden)     # save `masked` as the evidence content
    vault.kinds(evidence_id)            # what can be shown, without the values
    vault.reveal(evidence_id, index)    # only after the approval

The vault never decides who may see a value. The API checks the `disclosure`
approval (it expires and is single use), writes the audit line, and returns the
value to the person only. A real value is never logged, saved in the database,
sent to the AI or stored in Qdrant.
"""

import json
import os
import re
import secrets
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from reconix_ai.harness.masking import MASK_RULES, MaskRule, label


@dataclass(frozen=True)
class HiddenValue:
    index: int  # 0 for the first label mask_and_keep added, 1 for the next, ...
    kind: str  # the label's type, e.g. "password"
    start: int  # where its label starts in the masked text
    value: str  # the real value: never log, save or send it


@dataclass(frozen=True)
class HiddenKind:
    """A hidden value without the value, for the approval request and the screen."""

    index: int
    kind: str
    start: int


class DisclosureError(Exception):
    """code: BAD_EVIDENCE_ID, NOT_FOUND, BAD_INDEX or UNREADABLE."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Cipher(Protocol):
    """cryptography's Fernet fits; the API passes one made from RECONIX_PROVIDER_ENCRYPTION_KEY."""

    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, token: bytes) -> bytes: ...


def mask_and_keep(text: str) -> tuple[str, int, list[HiddenValue]]:
    """Like mask_secrets (same masked text, same count), plus the real values.

    Each secret first gets a numbered label with a random tag, so it can be found
    again after the later rules have run, then the labels become the normal ones.
    A secret that ends up inside a later secret (a key inside a cookie, say) is
    kept as part of that one.
    """
    tag = secrets.token_hex(4)
    found: dict[int, tuple[str, str]] = {}
    total = 0
    for rule in MASK_RULES:
        text, count = keep_rule(rule, text, tag, found)
        total += count
    masked, hidden = finish(text, tag, found)
    return masked, total, hidden


def keep_rule(
    rule: MaskRule, text: str, tag: str, found: dict[int, tuple[str, str]]
) -> tuple[str, int]:
    """masking.apply_rule, but the label is numbered and the real value is kept."""
    count = 0

    def swap(match: re.Match[str]) -> str:
        nonlocal count
        if rule.group is None:
            start, end = match.start(), match.end()
        elif match.group(rule.group).startswith("[MASKED:"):
            return match.group(0)  # already masked by an earlier rule
        else:
            start, end = match.start(rule.group), match.end(rule.group)
        count += 1
        number = len(found)
        found[number] = (rule.kind, restore(match.string[start:end], tag, found))
        whole = match.group(0)
        return (
            whole[: start - match.start()]
            + f"[MASKED:{rule.kind}#{tag}-{number}]"
            + whole[end - match.start() :]
        )

    return rule.pattern.sub(swap, text), count


def numbered_labels(tag: str) -> re.Pattern[str]:
    return re.compile(r"\[MASKED:(?P<kind>[a-z_]+)#" + tag + r"-(?P<number>\d+)\]")


def restore(value: str, tag: str, found: dict[int, tuple[str, str]]) -> str:
    """Put back the real values of labels inside a value; they are kept as part of it."""

    def swap(match: re.Match[str]) -> str:
        _, real = found.pop(int(match["number"]))
        return real

    return numbered_labels(tag).sub(swap, value)


def finish(text: str, tag: str, found: dict[int, tuple[str, str]]) -> tuple[str, list[HiddenValue]]:
    """Numbered labels -> normal labels, and the values in the order they appear."""
    parts: list[str] = []
    hidden: list[HiddenValue] = []
    size = last = 0
    for match in numbered_labels(tag).finditer(text):
        before = text[last : match.start()]
        kind, value = found[int(match["number"])]
        parts += [before, label(kind)]
        size += len(before)
        # A label a later rule cut in half is gone from the text; never keep its pieces.
        if f"#{tag}-" not in value:
            hidden.append(HiddenValue(index=len(hidden), kind=kind, start=size, value=value))
        size += len(label(kind))
        last = match.end()
    parts.append(text[last:])
    return "".join(parts), hidden


class DisclosureVault:
    """Real values, one encrypted file per evidence, in a folder only this user can open."""

    def __init__(self, folder: str | Path, cipher: Cipher) -> None:
        self.folder = Path(folder)
        self.cipher = cipher

    def keep(self, evidence_id: UUID | str, hidden: Sequence[HiddenValue]) -> None:
        """Save the real values of one evidence. Nothing hidden: nothing saved."""
        if not hidden:
            return
        path = self.path(evidence_id)
        self.open_folder()
        rows = [{"kind": item.kind, "start": item.start, "value": item.value} for item in hidden]
        data = self.cipher.encrypt(json.dumps(rows).encode())
        temporary = path.with_suffix(f".{secrets.token_hex(4)}.tmp")
        # 0o600 and O_EXCL | O_NOFOLLOW: a new file only this user can read, never
        # written through a symlink. The rename makes the save all or nothing.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(data)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def kinds(self, evidence_id: UUID | str) -> list[HiddenKind]:
        """What can be shown for one evidence, without the values. None kept: []."""
        try:
            rows = self.read(evidence_id)
        except DisclosureError as error:
            if error.code == "NOT_FOUND":
                return []
            raise
        return [HiddenKind(index, row["kind"], row["start"]) for index, row in enumerate(rows)]

    def reveal(self, evidence_id: UUID | str, index: int) -> HiddenValue:
        """One real value. Call it only for an approved, unused `disclosure` approval."""
        rows = self.read(evidence_id)
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(rows):
            raise DisclosureError("BAD_INDEX")
        row = rows[index]
        return HiddenValue(index=index, kind=row["kind"], start=row["start"], value=row["value"])

    def forget(self, evidence_id: UUID | str) -> None:
        """Delete the real values of one evidence, for example with its assessment."""
        self.path(evidence_id).unlink(missing_ok=True)

    def path(self, evidence_id: UUID | str) -> Path:
        # Only a real UUID becomes a file name, so no id can point outside the folder.
        try:
            name = str(UUID(str(evidence_id)))
        except ValueError:
            raise DisclosureError("BAD_EVIDENCE_ID") from None
        return self.folder / f"{name}.vault"

    def open_folder(self) -> None:
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not stat.S_ISDIR(os.lstat(self.folder).st_mode):
            raise NotADirectoryError(f"{self.folder} is not a folder")  # e.g. a symlink
        os.chmod(self.folder, stat.S_IRWXU)  # also fixes a folder made earlier with other rights

    def read(self, evidence_id: UUID | str) -> list[dict]:
        path = self.path(evidence_id)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise DisclosureError("NOT_FOUND") from None
        except OSError:
            raise DisclosureError("UNREADABLE") from None  # e.g. a symlink
        with os.fdopen(descriptor, "rb") as file:
            data = file.read()
        try:
            rows = json.loads(self.cipher.decrypt(data))
        except Exception:
            raise DisclosureError("UNREADABLE") from None  # wrong key or a damaged file
        return rows
