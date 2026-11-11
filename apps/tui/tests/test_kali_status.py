"""The session bar's Kali MCP status chip and its Core API feed (store + Pilot)."""

from reconix import store, theme
from reconix.widgets.chrome import SessionBar

from .support import SIZE, settle


def _bar_text(app) -> str:
    bar = app.screen.query_one(SessionBar)
    bar.refresh_line()
    return str(bar.render())


def _dot_color(form) -> str:
    return form.spans[-1].style             # the `●` segment's style


# --- the store seam / chip forms --------------------------------------------------------------
def test_kali_defaults_to_unknown():
    assert store.kali_status() == "UNKNOWN" and store.kali_host() is None
    forms = SessionBar._kali_forms()
    assert len(forms) == 1 and str(forms[0]) == "kali ●"
    assert _dot_color(forms[0]) == theme.MUTED


# --- the Core API feed (store.refresh_kali) ---------------------------------------------------
def test_refresh_maps_connected_to_reachable(fake_api):
    fake_api.kali_connected = True
    store.refresh_kali()
    assert store.kali_status() == "REACHABLE"
    assert store.kali_host() == "reconix-kali-container:8000"


def test_refresh_maps_disconnected_to_unreachable(fake_api):
    fake_api.kali_connected = False
    store.refresh_kali()
    assert store.kali_status() == "UNREACHABLE" and store.kali_host() is None


def test_refresh_falls_back_to_unknown_when_core_api_down(fake_api):
    fake_api.down = True                          # the Core API itself is unreachable
    store.set_kali_status("REACHABLE", "stale")   # prove the fallback clears a stale value
    store.refresh_kali()
    assert store.kali_status() == "UNKNOWN" and store.kali_host() is None


# --- the chip in the bar ----------------------------------------------------------------------
async def test_kali_chip_renders_and_dot_reflects_status(app):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        store.set_kali_status("UNKNOWN", None)
        assert "kali ●" in _bar_text(app)                 # UNKNOWN: short form, muted dot
        assert _dot_color(SessionBar._kali_forms()[-1]) == theme.MUTED

        store.set_kali_status("REACHABLE", host="kali.local")
        assert "kali: kali.local ●" in _bar_text(app)      # long form with the host
        assert _dot_color(SessionBar._kali_forms()[0]) == theme.GREEN

        store.set_kali_status("UNREACHABLE")
        assert _dot_color(SessionBar._kali_forms()[-1]) == theme.CRITICAL


async def test_the_bar_reflects_a_reachable_kali_after_a_poll(app, fake_api):
    fake_api.kali_connected = True
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        store.refresh_kali()                               # the poll's work, run inline
        assert store.kali_status() == "REACHABLE"
        assert "kali: reconix-kali-container:8000 ●" in _bar_text(app)
        assert _dot_color(SessionBar._kali_forms()[0]) == theme.GREEN
