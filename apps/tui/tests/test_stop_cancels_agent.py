"""Stopping the run stops an agent turn too, but only once the store has really stopped it."""

from reconix import store

from .support import SIZE, run_to, settle, show


def _spy_cancel(app, monkeypatch) -> list:
    calls = []
    monkeypatch.setattr(app, "cancel_agent",
                        lambda mark_stopped=True: calls.append(mark_stopped))
    return calls


async def test_a_stop_cancels_the_agent_once_without_marking_it_again(app, monkeypatch):
    run_to("approval:approval-001")
    calls = _spy_cancel(app, monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "execution")
        await pilot.press("ctrl+c")
        await settle(pilot)
        await pilot.press("down", "enter")                       # Stop now
        await settle(pilot)
        assert store.get_run().stopped == "you stopped it"
        assert calls == [False]


async def test_a_failed_stop_leaves_the_agent_alone(app, monkeypatch):
    run_to("approval:approval-001")
    calls = _spy_cancel(app, monkeypatch)

    def refuse() -> None:
        raise store.StoreValidationError("No assessment is running.")

    monkeypatch.setattr(store, "stop_run", refuse)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "execution")
        app.stop_run()
        await settle(pilot)
        assert calls == [] and not store.get_run().stopped
