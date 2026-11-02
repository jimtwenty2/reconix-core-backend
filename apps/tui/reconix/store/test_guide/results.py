"""The evaluator's results: one mark (PASS / FAIL / SKIP) and a note per case.

Saved after every change to `results.json` in the results folder (RECONIX_TEST_RESULTS_DIR,
default ~/.reconix/test-results), so a crash or a quit loses nothing. `export()` writes a
dated Markdown report and a JSON copy next to it. Notes are masked (store/redact) before they
are saved, so a secret typed into a note never lands on disk.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Tuple

from ..errors import StoreValidationError
from ..persist import _private_dir
from ..redact import clean, redact
from .model import MARKS, Flow, Result

MAX_NOTE = 500
RESULTS_FILE = "results.json"


def results_dir() -> Path:
    return Path(
        os.environ.get("RECONIX_TEST_RESULTS_DIR") or "~/.reconix/test-results"
    ).expanduser()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load() -> Dict[str, Result]:
    """Every saved result by case id (an unreadable file reads as no results)."""
    path = results_dir() / RESULTS_FILE
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: Dict[str, Result] = {}
    for case_id, item in (raw.get("results") or {}).items():
        if isinstance(item, dict) and item.get("mark", "") in MARKS + ("",):
            out[str(case_id)] = Result(
                item.get("mark", ""), str(item.get("note", "")), str(item.get("at", ""))
            )
    return out


def _write(path: Path, text: str) -> None:
    """Write `text` atomically, readable by this user only (folder 0700, file 0600). A random
    temp name opened with O_EXCL, so a planted file or symlink is never followed."""
    _private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _save(results: Dict[str, Result]) -> None:
    data = {"results": {cid: r.__dict__ for cid, r in sorted(results.items())}}
    _write(results_dir() / RESULTS_FILE, json.dumps(data, indent=2, ensure_ascii=False))


def set_mark(case_id: str, mark: str) -> Result:
    """Mark a case PASS, FAIL or SKIP (the same mark again clears it)."""
    mark = mark.upper()
    if mark not in MARKS:
        raise StoreValidationError(f"A mark is one of {', '.join(MARKS)}.")
    results = load()
    old = results.get(case_id, Result())
    new = Result("" if old.mark == mark else mark, old.note, _now())
    results[case_id] = new
    _save(results)
    return new


def set_note(case_id: str, note: str) -> Result:
    """Attach a note (masked, one line, at most 500 characters; empty clears it)."""
    text = " ".join(redact(clean(note or "")).split())
    if len(text) > MAX_NOTE:
        raise StoreValidationError(f"Keep the note under {MAX_NOTE} characters.")
    results = load()
    old = results.get(case_id, Result())
    results[case_id] = Result(old.mark, text, _now())
    _save(results)
    return results[case_id]


def counts(flows: Iterable[Flow], results: Dict[str, Result]) -> Dict[str, int]:
    """How many cases are PASS, FAIL, SKIP and not tested yet."""
    out = {mark: 0 for mark in MARKS}
    out["TODO"] = 0
    for flow in flows:
        for case in flow.cases:
            mark = results.get(case.id, Result()).mark
            out[mark or "TODO"] += 1
    return out


def export(flows: Tuple[Flow, ...]) -> Tuple[Path, Path]:
    """Write `results-<date>.md` and `.json` with every case and its mark; returns both paths."""
    results = load()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    folder = results_dir()
    md_path, json_path = folder / f"results-{stamp}.md", folder / f"results-{stamp}.json"
    total = counts(flows, results)
    lines = [
        "# Reconix static TUI: test results",
        "",
        f"Exported {_now()} · PASS {total['PASS']} · FAIL {total['FAIL']} · "
        f"SKIP {total['SKIP']} · not tested {total['TODO']}",
        "",
    ]
    rows = []
    for flow in flows:
        lines += [
            f"## {flow.number} {flow.title}",
            "",
            "| Case | Title | Result | Note |",
            "|---|---|---|---|",
        ]
        for case in flow.cases:
            r = results.get(case.id, Result())
            note = r.note.replace("|", "\\|")
            lines.append(f"| {case.id} | {case.title} | {r.mark or '—'} | {note} |")
            rows.append(
                {
                    "id": case.id,
                    "flow": flow.id,
                    "title": case.title,
                    "mark": r.mark,
                    "note": r.note,
                    "at": r.at,
                }
            )
        lines.append("")
    _write(md_path, "\n".join(lines))
    _write(json_path, json.dumps({"exported_at": _now(), "totals": total, "cases": rows},
                                 indent=2, ensure_ascii=False))
    return md_path, json_path
