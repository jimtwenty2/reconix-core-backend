"""Each template driven through the UI on the Core API's run (the fake API) to the report;
a source-code scope can't be sent to the API yet, so its approval is refused plainly."""

from pathlib import Path

import pytest
from textual.widgets import DataTable

from reconix import store
from reconix.screens import ChoiceScreen, FindingsListScreen, ReportScreen

from .support import SIZE, TEST_PASSWORD, pass_gate, run_ui_to, settle, wait_for_run

# (request, template, the host the API's findings are on)
CASES = [
    pytest.param("test the API at https://api.example.com/v1", "api", "api.example.com", id="api"),
    pytest.param("Assess 192.0.2.10", "network", "192.0.2.10", id="network-host"),
    pytest.param("Assess 10.0.0.0/24", "network", "10.0.0.0/24", id="network-cidr"),
]


@pytest.mark.parametrize("request_text, template_id, host", CASES)
async def test_template_runs_through_the_ui_to_an_exported_report(
    app, fake_api, request_text, template_id, host
):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None, request=request_text)
        assert store.get_assessment().template_id == template_id
        assert store.is_completed()
        assert fake_api.tool_runs() == ["NMAP", "NUCLEI", "SQLMAP"]  # Kali ran each step
        findings = store.list_findings()
        assert len(findings) == 2 and all(host in f.path for f in findings)

        app.goto("findings")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)
        assert app.screen.query_one(DataTable).row_count == 2

        await pilot.press("alt+8")
        await settle(pilot)
        assert isinstance(app.screen, ReportScreen)
        await pilot.press("j")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        path = Path(store.get_run().report_path)
        assert path.suffix == ".json" and path.exists()
        saved = path.read_text(encoding="utf-8")
        assert TEST_PASSWORD not in saved and "fake-session-token" not in saved


async def test_a_source_repo_url_shows_the_apis_clone_error(app, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request="Review https://github.com/acme/app")
        assert store.get_assessment().template_id == "source"
        await pass_gate(app, pilot)  # Approve the scope
        await wait_for_run(pilot)
        assert store.get_scope().status == "APPROVED"
        assert any(p.endswith("/code/clone") for p in fake_api.paths())
        assert store.get_assessment().live.failed.startswith("GIT_NOT_FOUND")  # as the API said
        assert not any(p.endswith("/submit") for p in fake_api.paths())
        assert fake_api.tool_runs() == []
