"""Edit params: an action from the Core API has nothing the app may edit.

The API checked the exact tool call it holds for you (S1/S2) and runs only that one; "Edit
params" was for the app's own scripted actions, which no longer exist. A step to run
differently is the AI's next step, checked by the API again.
"""

import pytest

from reconix import store

from .support import decide, play_until_gate, run_to


def _api_gate() -> str:
    run_to("plan")
    decide("plan")
    gate = play_until_gate()
    assert gate.startswith("approval:")
    return gate.split(":", 1)[1]


def test_an_api_action_cannot_be_edited(fake_api):
    request_id = _api_gate()
    assert not store.can_edit(request_id)
    with pytest.raises(store.StoreValidationError, match="nothing to edit"):
        store.edit_approval(request_id, "/somewhere-else")


def test_an_unknown_action_is_refused(fake_api):
    _api_gate()
    with pytest.raises(store.StoreValidationError, match="Unknown approval"):
        store.edit_approval("approval-999", "/x")
