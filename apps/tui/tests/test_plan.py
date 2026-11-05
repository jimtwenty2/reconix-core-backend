"""The dashboard plan: named tasks per template, their status read live from the run."""


from reconix import store

from .support import ASK_REQUEST, decide, play_until_gate, run_to


def test_there_is_no_plan_before_a_template_is_chosen():
    store.start_run(ASK_REQUEST)                # a bare hostname waits for the template
    assert store.plan_tasks() == []


def test_the_plan_is_named_for_the_chosen_template():
    run_to("scope")
    tasks = store.plan_tasks()
    assert [task.label for task in tasks] == [
        "Map the site", "Scan for weaknesses", "Validate findings",
        "Correlate & dedupe findings", "Generate report",
    ]
    # Nothing has run yet (scope not approved), so every task is pending.
    assert all(task.status == "pending" for task in tasks)


def test_each_template_names_its_own_plan():
    store.start_run("Review the repository at git@github.com:acme/app.git")
    # The repo picked Source Code at once, so its plan is there from the start.
    assert [task.label for task in store.plan_tasks()][:2] == [
        "Inventory the code", "Static, secret & dependency scans"]


def test_tasks_track_the_run_as_it_moves_through_the_phases():
    run_to("plan")
    decide("plan")
    assert play_until_gate().startswith("approval:")   # the LOW step ran, MEDIUM waits
    status = {task.key: task.status for task in store.plan_tasks()}
    assert status["discovery"] == "active"   # the API's discovery step ran
    assert status["validation"] == "pending"
    assert status["report"] == "pending"


def test_report_task_is_active_when_complete_then_done_once_generated():
    run_to(None)
    status = {task.key: task.status for task in store.plan_tasks()}
    assert status["analysis"] == "done"       # the API's analysis came back
    assert status["report"] == "active"       # complete, report not generated yet
    store.generate_report("json")
    assert {t.key: t.status for t in store.plan_tasks()}["report"] == "done"


def test_every_phase_that_ran_is_done_when_the_run_ends():
    run_to(None)
    status = {task.key: task.status for task in store.plan_tasks()}
    assert status["discovery"] == status["scanning"] == status["validation"] == "done"
