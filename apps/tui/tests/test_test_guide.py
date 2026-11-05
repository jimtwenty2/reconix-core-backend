"""The evaluator test guide: its cases, the generated docs, saved results and the /tests screen,
plus the guide's main-flow questions walked end to end in the UI (so the docs stay true)."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

from reconix import store
from reconix.screens import TestGuideScreen
from reconix.store import test_guide
from reconix.store.test_guide import results

from .support import SIZE, TEST_PASSWORD, run_ui_to, settle

ID = re.compile(r"^[A-Z]+(?:-[A-Z]+)*-\d{2}$")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "make_test_docs.py"


@pytest.fixture(autouse=True)
def results_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("RECONIX_TEST_RESULTS_DIR", str(tmp_path / "test-results"))
    return tmp_path / "test-results"


def _docs_module():
    spec = importlib.util.spec_from_file_location("make_test_docs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- the cases ------------------------------------------------------------------------------
def test_every_case_is_complete_and_its_id_is_unique():
    seen = set()
    for flow in test_guide.list_flows():
        assert flow.cases, flow.id
        for case in flow.cases:
            assert ID.match(case.id) and case.id.startswith(flow.id + "-"), case.id
            assert case.id not in seen
            seen.add(case.id)
            assert case.title and case.steps and case.expect, case.id
    assert len(seen) == len(test_guide.all_cases())


def test_each_template_has_five_cases_with_a_question():
    for flow_id in ("MF-WEB", "MF-API", "MF-NET", "MF-SRC"):
        flow = next(f for f in test_guide.list_flows() if f.id == flow_id)
        assert len(flow.cases) == 5 and all(c.ask for c in flow.cases), flow_id


def test_the_generated_docs_are_up_to_date():
    module = _docs_module()
    for name, text in module.build().items():
        path = module.DOCS / name
        assert path.is_file() and path.read_text(encoding="utf-8") == text, (
            f"docs/evaluator/{name} is stale: run python scripts/make_test_docs.py"
        )


def test_every_case_is_in_the_docs():
    module = _docs_module()
    pages = "".join(module.build().values())
    for case_id in test_guide.all_cases():
        assert f"{case_id} ·" in pages, case_id


# --- saved results --------------------------------------------------------------------------
def test_a_mark_is_saved_and_the_same_mark_again_clears_it(results_dir):
    assert results.set_mark("MF-WEB-01", "pass").mark == "PASS"
    assert results.load()["MF-WEB-01"].mark == "PASS"
    assert (results_dir / "results.json").is_file()
    assert results.set_mark("MF-WEB-01", "PASS").mark == ""
    with pytest.raises(store.StoreValidationError):
        results.set_mark("MF-WEB-01", "MAYBE")


def test_a_secret_in_a_note_is_masked_before_it_is_saved(results_dir):
    results.set_note("PROV-02", f"login https://demo:{TEST_PASSWORD}@sso.example.com failed")
    saved = (results_dir / "results.json").read_text(encoding="utf-8")
    assert TEST_PASSWORD not in saved and "••••" in saved


def test_export_writes_markdown_and_json(results_dir):
    results.set_mark("MF-NET-01", "PASS")
    results.set_mark("MF-NET-02", "FAIL")
    md_path, json_path = results.export(test_guide.list_flows())
    text = md_path.read_text(encoding="utf-8")
    assert (
        "PASS 1 · FAIL 1" in text
        and "| MF-NET-02 | Ports in the question fill the scope | FAIL |" in text
    )
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["totals"]["PASS"] == 1 and len(data["cases"]) == len(test_guide.all_cases())


# --- the /tests screen ----------------------------------------------------------------------
async def test_tests_command_opens_the_checklist_and_marks_a_case(app, results_dir):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.run_command_line("/tests")
        await settle(pilot)
        assert isinstance(app.screen, TestGuideScreen)
        first = app.screen.current_case()
        assert first.id == "PROV-01"
        await pilot.press("p")
        await settle(pilot)
        assert results.load()["PROV-01"].mark == "PASS"
        await pilot.press("e")
        await settle(pilot)
        assert list(results_dir.glob("results-*.md")) and list(results_dir.glob("results-*.json"))
        await pilot.press("escape")
        await settle(pilot)
        assert not isinstance(app.screen, TestGuideScreen)
        assert not store.get_run().started  # the checklist changes nothing


# --- the guide's main flow, as the evaluator types it ---------------------------------------
@pytest.mark.parametrize("case_id", ["MF-WEB-01", "MF-API-01", "MF-NET-01"])
async def test_each_templates_first_case_runs_to_the_end(app, case_id, fake_api):
    """The guide's first line per template runs on the Core API (the fake API here): every
    step, approval and finding comes from it."""
    case = test_guide.find_case(case_id)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None, case.ask)
        await settle(pilot)
    assert store.is_finished() and not store.get_run().stopped
    assert fake_api.tool_runs() == ["NMAP", "NUCLEI", "SQLMAP"]
    titles = [f.title for f in store.list_findings()]
    assert titles == ["Exposed admin panel", "Open port 3000/tcp (http)"]   # worst first
    chat = " ".join(entry.text for entry in store.list_chat())
    assert TEST_PASSWORD not in chat


def test_the_source_case_is_refused_by_the_core_api_for_now():
    """A source-code scope needs its code uploaded to the API first (the code-scan flow)."""
    from .support import play_until_gate

    store.submit_prompt(test_guide.find_case("MF-SRC-01").ask)
    assert play_until_gate() == "scope"
    with pytest.raises(store.StoreValidationError, match="source-code scope"):
        store.approve_scope()
    assert store.get_scope().status == "DRAFT"


def test_bare_hostname_waits_for_the_template():
    store.submit_prompt(test_guide.find_case("MF-WEB-02").ask)
    while store.advance() is not None and not store.waiting_gate():
        pass
    assert store.waiting_gate() == "template"


def test_ports_in_the_question_are_the_scope():
    store.submit_prompt(test_guide.find_case("MF-NET-02").ask)
    assert store.get_scope().allowed_ports == [22, 443, 8443]


@pytest.mark.parametrize(
    "line, message",
    [
        ("scan 10.0.0.300", "isn't a valid IPv4 address"),
        ("scan 10.0.0.0/8", "too wide to test"),
        ("scan 10.0.0.20-10.0.0.1", "runs backwards"),
        ("scan 10.0.0.1-10.0.0.20", "Dash ranges aren't supported"),
        ("review repo github.com/acme", "isn't a repository"),
    ],
)
def test_refused_targets_say_why_and_start_nothing(line, message):
    with pytest.raises(store.StoreValidationError, match=message):
        store.submit_prompt(line)
    assert not store.get_run().started


def test_a_dash_range_in_a_sentence_is_never_cut_to_its_first_address():
    """Regression: "scan 10.0.0.1-10.0.0.20" used to start a run on 10.0.0.1 alone."""
    with pytest.raises(store.StoreValidationError):
        store.submit_prompt("scan 10.0.0.1-10.0.0.20 for open ports")
    with pytest.raises(store.StoreValidationError):
        store.check_target("network", "10.0.0.1-10.0.0.9")
    assert store.get_assessment().target in ("", None)


def test_a_stopped_assessment_has_no_report_yet():
    from .support import decide, play_until_gate, run_to

    run_to("plan", test_guide.find_case("MF-WEB-05").ask)
    decide("plan")
    assert play_until_gate().startswith("approval:")   # the fake API's MEDIUM step waits
    store.stop_run()                     # (a Reject no longer stops the run: QA-003)
    assert store.get_run().stopped
    with pytest.raises(
        store.StoreValidationError, match="available once the assessment is complete"
    ):
        store.generate_report("pdf")


@pytest.mark.parametrize("line", [
    "scan 10.0.0.1–10.0.0.20",        # en dash
    "scan 10.0.0.1 - 10.0.0.20",
    "scan 10.0.0.1 -10.0.0.20",
    "scan 10.0.0.1..10.0.0.20",
    "scan 10.0.0.1 to 10.0.0.20",
])
def test_every_range_spelling_is_refused_never_cut_to_one_address(line):
    with pytest.raises(store.StoreValidationError):
        store.submit_prompt(line)
    assert not store.get_run().started


def test_results_are_written_for_this_user_only(results_dir):
    import os
    import stat

    results.set_mark("CMD-01", "PASS")
    md_path, json_path = results.export(test_guide.list_flows())
    if hasattr(os, "getuid"):
        assert stat.S_IMODE(results_dir.stat().st_mode) == 0o700
        for path in (results_dir / "results.json", md_path, json_path):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
