"""App-state fixes: the Kali poll, the model chip across sessions, the start-up provider
question and its recommended choice, and the report export off the UI thread (Pilot)."""

import threading

from reconix import core_api, store
from reconix.app import ReconixApp
from reconix.models import ActiveModel
from reconix.screens import ChoiceScreen
from reconix.widgets.chrome import SessionBar

from .support import SIZE, run_to, settle, show, wait_until


def _add_reconix(fake_api, local: bool = True) -> dict:
    row = fake_api._add_provider(
        {"provider_type": "RECONIX", "display_name": "Reconix", "model_name": "reconix"}
    )
    row["is_local"] = local
    return row


# --- 1. the Kali chip is polled ---------------------------------------------------------------
async def test_the_app_polls_kali_and_the_chip_turns_green(app, fake_api, monkeypatch):
    monkeypatch.setattr(ReconixApp, "CHECK_CORE_API_ON_START", True)
    monkeypatch.setattr(ReconixApp, "poll_core_api", lambda self: None)  # not under test
    fake_api.kali_connected = True
    intervals = []
    real = ReconixApp.set_interval
    monkeypatch.setattr(
        ReconixApp,
        "set_interval",
        lambda self, secs, cb, **kw: (
            intervals.append((secs, cb.__name__)),
            real(self, secs, cb, **kw),
        )[1],
    )
    assert store.kali_status() == "UNKNOWN"
    async with app.run_test(size=SIZE) as pilot:
        await wait_until(pilot, lambda: store.kali_status() == "REACHABLE", what="kali poll")
        await settle(pilot)
        assert (ReconixApp.KALI_POLL_SECONDS, "poll_kali") in intervals
        assert "kali: reconix-kali-container:8000 ●" in str(
            app.screen.query_one(SessionBar).render()
        )


# --- 2. the model chip survives a new API session ---------------------------------------------
def test_active_model_survives_a_new_session(fake_api):
    row = _add_reconix(fake_api)
    fake_api._make_active(row["llm_provider_id"])
    store.list_providers()  # reads the rows into the cache
    assert store.active_model() is not None
    core_api.connect.reset()  # what opening another assessment does
    assert store.active_model() == ActiveModel("reconix", "reconix", "Reconix (default)")


# --- 3. the start-up provider question --------------------------------------------------------
async def test_no_question_when_a_provider_is_active(app, fake_api, monkeypatch):
    monkeypatch.setattr(ReconixApp, "ASK_PROVIDER_ON_START", True)
    fake_api._make_active(_add_reconix(fake_api)["llm_provider_id"])
    async with app.run_test(size=SIZE) as pilot:
        await wait_until(pilot, lambda: store.active_model() is not None, what="rows read")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)


async def test_the_recommended_choice_activates_the_reconix_provider(app, fake_api, monkeypatch):
    monkeypatch.setattr(ReconixApp, "ASK_PROVIDER_ON_START", True)
    _add_reconix(fake_api)
    async with app.run_test(size=SIZE) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, ChoiceScreen), what="question")
        choice = next(c for c in app.screen._choices if c.recommended)
        assert choice.id == "reconix"
        app.screen.dismiss("reconix")
        await wait_until(pilot, lambda: store.active_model() is not None, what="activated")
        assert store.active_model().provider_id == "reconix"
        assert fake_api._provider(fake_api.providers[0]["llm_provider_id"])["is_active"]


async def test_the_recommended_choice_off_this_computer_asks_for_ok(app, fake_api, monkeypatch):
    monkeypatch.setattr(ReconixApp, "ASK_PROVIDER_ON_START", True)
    _add_reconix(fake_api, local=False)
    async with app.run_test(size=SIZE) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, ChoiceScreen), what="question")
        app.screen.dismiss("reconix")
        await wait_until(pilot, store.core_api_needs_ok, what="approval pending")
        await wait_until(
            pilot,
            lambda: (
                getattr(app.screen, "_chip", None) == "Approval"
                or "USE THIS MODEL" in str(getattr(app.screen, "_title", ""))
            ),
            what="approval dialog",
        )
        assert store.active_model() is None  # not active until the person approves


# --- 4. the report export runs off the UI thread ----------------------------------------------
async def test_report_export_runs_in_a_worker_with_a_note_that_stays(app, monkeypatch):
    run_to(None)
    release, started, thread = threading.Event(), threading.Event(), []
    real = store.generate_report

    def slow(fmt):
        thread.append(threading.current_thread())
        started.set()
        release.wait(5)
        return real(fmt)

    monkeypatch.setattr(store, "generate_report", slow)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "report")
        app.export_report("json")
        await wait_until(pilot, started.is_set, what="writer started")
        notes = [str(n.message) for n in app._notifications]
        assert any("Writing the JSON report" in m for m in notes)
        assert not isinstance(app.screen, ChoiceScreen)  # the UI stayed free
        release.set()
        await wait_until(pilot, lambda: isinstance(app.screen, ChoiceScreen), what="saved")
        assert thread[0] is not threading.main_thread()
        assert not any("Writing the" in str(n.message) for n in app._notifications)


async def test_report_export_refusal_is_immediate(app):
    async with app.run_test(size=SIZE) as pilot:
        app.export_report("json")
        await settle(pilot)
        assert app._notifications  # the store's reason, no worker involved
