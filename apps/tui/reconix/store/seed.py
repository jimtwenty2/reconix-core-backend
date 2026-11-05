"""The initial session state: a fresh, empty assessment ready for a target.

Nothing is baked in: the run is built from the target you type (see `store.parser` and
`store.templates`), and everything after the scope comes from the Core API. There is no
demo target, so a real scan is never one key away from a target nobody typed.
"""

from ..models import ActivityEntry, Assessment, ChatEntry
from . import lists

ASSESSMENT_PREFIX = "RCX"

WELCOME = ("Welcome to Reconix. Type a target — a URL, an IPv4 address or range, or a git "
           "repo or local path — or /template to pick a template.")


def _next_planned_id() -> str:
    return f"{ASSESSMENT_PREFIX}-{len(lists.ASSESSMENTS) + 1:03d}"


def build_assessment() -> Assessment:
    """A fresh, not-yet-started assessment: no target or script until the operator types one."""
    return Assessment(
        planned_id=_next_planned_id(), target="", target_url="", target_kind="target",
        operator="analyst",
        chat=[ChatEntry("text", "reconix", WELCOME, seq=lists.next_seq())],
        activity=[ActivityEntry("SYS", "Session started · Core API",
                                seq=lists.next_seq())],
    )


def add_assessment(assessment: Assessment) -> Assessment:
    """Append an assessment and make it the current one."""
    lists.ASSESSMENTS.append(assessment)
    lists.CURRENT[0] = len(lists.ASSESSMENTS) - 1
    return assessment


def load_run_data() -> Assessment:
    """Add a fresh assessment and make it current (keeps earlier ones)."""
    return add_assessment(build_assessment())


def load_demo_data() -> None:
    """Empty everything (incl. the audit trail and history) and load one fresh assessment."""
    lists.reset()
    load_run_data()
