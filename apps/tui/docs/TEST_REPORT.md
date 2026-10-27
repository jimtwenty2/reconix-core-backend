# Test report: Reconix TUI

---

## Reconix Plan Screen — Implementation and Regression Tests

**Date / time:** 2026-10-27 16:37 (UTC+7)
**Branch / commit:** `ui/tui/plan-review-screen`, based on `Develop` at `379f244`; changes
uncommitted at run time
**Feature under test:** the Plan screen (`apps/tui/reconix/screens/plan.py`): rows, states,
menu actions, keyboard, live status updates, layout
**Final acceptance status:** **PASS, with one BLOCKED case and the follow-ups below.** Every
Plan-screen test that can run on this branch passes; the one BLOCKED case needs the
`terminal/input-validation` PR (see Merge order).

### Environment

| Item | Value |
|---|---|
| OS | Windows 10 Pro 10.0.19045 |
| Python | 3.12.10 (`apps/tui/.venv`) |
| UI framework | Textual 8.2.8 |
| Test runner | pytest 9.1.1, pytest-asyncio 1.4.1 |
| Lint | ruff 0.17.3 |
| Browser | None. The Plan screen is part of the native terminal app; Playwright doesn't apply. |
| Driver | Textual `App.run_test()` / Pilot (headless, real key presses into the real app) |
| Data | The app's demo data; steps play at once (`RunController.SPEED = 0`); no real target |

### Merge order

**`terminal/input-validation` should merge first.** It fixes "holding Enter on scope approval
runs the plan" (its gate menus ignore keys pressed within 0.5 s of appearing). After it merges,
remove the strict `xfail` marker from
`tests/test_plan_screen_ui.py::test_holding_enter_on_the_scope_never_runs_the_plan`; the test
then reports XPASS until the marker is gone.

### Baseline (before any change)

| Suite | Result |
|---|---|
| `test_plan.py`, `test_gates_ui.py`, `test_store_gates.py`, `test_execution_screen.py`, `test_navigation.py`, `test_approval_edit_ui.py`, `test_approval_edit.py` | 81 passed, 1 failed |

The failure, `test_execution_screen.py::test_scrolling_up_stops_following_until_end`, is a
known flaky test: it fails intermittently on the unchanged code too.

Problems found by inspecting and running the unchanged screen:

1. A run stopped while the plan ran said **"The plan has run."**, exactly like a finished run,
   with "View findings" recommended and no stopped message.
2. There was no **finished** state: a finished run reused the running state.
3. Long commands and labels **wrapped** instead of being cut.
4. Disabled "Edit steps" showed **"(not in demo)"**, not why it is disabled.

### Results per area

Kinds: **U** unit, **I** Pilot integration (real app), **E** end-to-end evidence run (real app,
screenshots). Logs: `../test-results/plan/plan-tests.log` (tests),
`../test-results/plan/results.json` (evidence run); both local only (gitignored).

| # | Area | Kind | Status | Test / evidence |
|---|---|---|---|---|
| 1 | State: none | I, E | PASS | `test_each_state_shows_its_panel_rows_and_actions[none]`, PLAN-01 |
| 2 | State: draft | I, E | PASS | `…[draft]`, PLAN-02 |
| 3 | State: busy (rows + spinner, no action) | I, E | PASS | `test_busy_shows_the_rows_and_a_spinner_and_offers_no_action`, PLAN-03 |
| 4 | State: ready | I, E | PASS | `…[ready]`, PLAN-04, [plan-ready.svg](test-evidence/plan-ready.svg) |
| 5 | State: running | I, E | PASS | `…[running]`, PLAN-05, [plan-running.svg](test-evidence/plan-running.svg) |
| 6 | State: stopped (before and while the plan ran) | I, E | PASS | `…[stopped]` ×2, `test_a_run_stopped_mid_plan_is_not_called_finished`, PLAN-07, [plan-stopped-mid-plan.svg](test-evidence/plan-stopped-mid-plan.svg) |
| 7 | State: finished | I, E | PASS | `…[finished]`, `test_finished_and_stopped_panels_keep_the_results`, PLAN-06, [plan-finished.svg](test-evidence/plan-finished.svg) |
| 8 | Row: number + label | U | PASS | `test_number_label_and_command_are_on_the_first_line` |
| 9 | Row: command or detail | U | PASS | same, `test_a_phase_row_shows_what_it_does_instead_of_a_command` |
| 10 | Row: risk word + dot, gate note | U | PASS | `test_risk_is_written_out_not_only_coloured` ×3, `test_each_gate_has_its_note` ×3 |
| 11 | Row: initial status (store values) | U | PASS | `test_each_store_status_has_its_label` ×4, `test_the_rows_start_with_the_stores_statuses` |
| 12 | Row: live transitions | I | PASS | `test_rows_follow_the_run_live` |
| 13 | Row: missing values safe | U | PASS | `test_missing_values_never_show_none`, `test_none_values_are_safe_too`, `test_an_unknown_status_is_shown_as_it_is_never_as_done` |
| 14 | Run plan starts once | I | PASS | `test_run_plan_starts_once_and_opens_execution` (one `plan.run` event) |
| 15 | Edit works when allowed | I | PASS | `test_edit_steps_opens_the_step_picker_when_allowed` |
| 16 | Edit disabled when not, reason shown | I, E | PASS | `test_edit_steps_is_disabled_and_says_why`, PLAN-08, [plan-edit-disabled.svg](test-evidence/plan-edit-disabled.svg) |
| 17 | Disabled Edit can't be chosen (digit, Enter, click, handler) | I | PASS | `test_disabled_edit_cannot_be_chosen_any_way` |
| 18 | Cancel goes to Template and back; nothing discarded | I | PASS | `test_cancel_goes_back_to_the_scope_and_the_plan_still_waits` |
| 19 | Repeated Run plan doesn't double-start | I | PASS | `test_choosing_run_plan_twice_still_starts_once` |
| 19b | Holding Enter on scope approval doesn't run the plan | I | **BLOCKED** | `test_holding_enter_on_the_scope_never_runs_the_plan` (strict xfail; see Merge order) |
| 20 | Approval gates still block | U, I | PASS | `test_every_gated_step_waits_for_its_approval`, `test_nothing_on_the_running_plan_screen_approves_a_step` |
| 21 | Tab both ways | I | PASS | `test_tab_toggles_between_menu_and_steps_both_ways` |
| 22 | Arrows move in the focused region | I | PASS | `test_arrows_move_in_the_focused_region_only` |
| 23 | Enter | I | PASS | `test_enter_runs_the_highlighted_action_and_enter_on_a_step_returns_to_it` |
| 24 | Esc per state | I | PASS | `test_esc_steps_from_the_list_to_the_menu_then_back`, `test_esc_in_busy_goes_back_even_from_the_list` |
| 25 | Live updates keep focus, selection, scroll | I | PASS | `test_live_updates_keep_focus_selection_and_scroll` |
| 26 | Duplicate / late events don't corrupt rows | I | PASS | `test_repeated_refreshes_never_duplicate_or_mix_up_rows` |
| 27 | Finished / stopped results shown | I | PASS | `test_finished_and_stopped_panels_keep_the_results`, `test_a_run_stopped_mid_plan_is_not_called_finished` |
| 28 | No overflow at 80×24 and 160×50 | I, E | PASS | `test_no_overflow_and_no_missing_parts` ×2, PLAN-10, PLAN-11, [plan-layout-80x24.svg](test-evidence/plan-layout-80x24.svg) |
| 29 | No missing parts | I | PASS | same test |
| 30 | Focus visible | I | PASS | `test_focus_is_always_on_a_visible_region`, `test_tab_toggles_…` |
| 31 | No duplicate rows / mixed statuses | I | PASS | `test_repeated_refreshes_…`, `test_rows_follow_the_run_live` |
| — | Long command cut with …; highlighted row in full | U, I, E | PASS | `test_a_long_command_is_cut_to_the_width`, `test_the_highlighted_row_shows_its_full_command`, PLAN-09 |

### Suite totals

| Suite | Result |
|---|---|
| `tests/test_plan_rows.py` (new, unit) | 21 passed |
| `tests/test_plan_screen_ui.py` (new, Pilot) | 30 passed, 1 xfailed (BLOCKED) |
| New + related suites (9 files) | 133 passed, 1 xfailed |
| Evidence run `scripts/capture_plan_evidence.py` | 11 of 11 passed |
| Full TUI suite | 970 passed, 27 skipped, 1 xfailed, 19 failed, 4 errors (`../test-results/plan/full-suite.log`) |
| `ruff check .` | passed |

**Full-suite failures are not from this change.** The 19 failures and 4 errors are the
Windows-only set (0600 file permissions, symlinks `WinError 1314`, FIFOs in
`test_knowledge_cli.py`, `test_knowledge_store.py`, `test_llm_providers.py`, `test_openapi.py`,
`test_persist.py`, `test_web_dashboard.py`; setup errors in `test_yaml_safe.py`). They fail on
`379f244` (Develop) without this change, and this branch touches none of those files.

**The new tests catch the old behaviour.** Run against the unchanged `plan.py`, the screen tests
for the finished and stopped-mid-plan states, the results panels, the disabled-Edit reason,
Esc in busy and overflow at both sizes fail. Most row tests also fail there, but only because
the old `plan_line()` takes no width.

### Scope and approval checks

| Check | Result |
|---|---|
| Run plan only starts through `store.run_plan()`; a second start is refused by the store | PASS (one `plan.run` event after two picks and a direct second call) |
| Every MEDIUM / HIGH step waits at its own approval gate, undecided until a decision | PASS (all approval ids reached their gate with no decision recorded) |
| Keys on the running Plan screen (Tab, ↓, Enter, Esc) decide no approval | PASS |
| Cancel keeps the run waiting at the plan gate; nothing discarded | PASS |
| Disabled Edit refused by the menu and by `app.edit_plan_steps()` | PASS |
| Holding Enter on scope approval can't run the plan | BLOCKED (needs `terminal/input-validation`) |

### Bugs found and fixed (all in `reconix/screens/plan.py`)

| ID | Bug | Fix | Retest |
|---|---|---|---|
| PLAN-BUG-1 | A run stopped while the plan ran said "The plan has run." | `state()` returns `stopped` for any stop; the stopped panel says "What ran is kept.", keeps "View findings" / "View execution" and adds "■ Stopped: N done · M not run". | Areas 6 and 27 PASS |
| PLAN-BUG-2 | No finished state | `state()` returns `finished` from the store's `completed` flag (no new state variable); its own question and "■ Finished:" counts. | Area 7 PASS |
| PLAN-BUG-3 | Long commands and labels wrapped | `plan_line(row, width, full)` cuts them with … to the list's width; the highlighted row shows them whole. | Area 28 and the long-command tests PASS |
| PLAN-BUG-4 | Missing values could print "None" | Missing values show "—"; empty scope chips are left out; an unknown status shows as its own text. | Area 13 PASS |
| PLAN-BUG-5 | Esc on the step list in the busy state did nothing (no menu to return to) | Esc goes back to Template there; Tab focuses the step list in busy. | Area 24 PASS |
| PLAN-BUG-6 | Disabled Edit gave no reason | A note under the menu: "Edit steps is unavailable: no gated step can be changed right now." | Area 16 PASS (see follow-up 1) |

**Behaviour change:** Esc in the busy state now goes back to the Template screen (before, with
the step list focused, it did nothing). Cancel and Esc are otherwise unchanged: Cancel goes to
the Template screen; Esc moves from the step list to the menu, then back to Template.

### Found, not fixed here

**Holding Enter while approving the scope runs the plan.** Reproduced: the third key repeat
(about 80 ms after the approval) picks "Run plan" the moment its gate appears, before anyone
could read the plan. The fix (gate menus ignore keys pressed within 0.5 s of appearing) is in
`widgets/choice_menu.py` on `terminal/input-validation`, which this branch must not edit.

### Follow-ups

1. **"(not in demo)" next to the disabled Edit.** A `Choice` can't carry its own disabled text:
   `widgets/choice_menu.py` hard-codes "(not in demo)" for every disabled choice. The note under
   the menu gives the real reason, and a test checks both texts so the double message isn't
   silent. Fix: a `disabled_note` field on `Choice` that `ChoiceMenu` shows instead (with the
   `terminal/input-validation` changes to that file).
2. **UPPERCASE enums (for Pojim).** `AGENTS.md` asks for UPPERCASE enum values, but plan statuses
   are lowercase (`pending`, `active`, `done`, `rejected`) and part of the web contract
   (`store/snapshot.py` → `web/src/lib/data/schema.ts`). Changing them needs the TUI and the web
   together. This screen shows only statuses the store really has (no `failed` or `skipped`).
3. **Disabled Edit never happens with demo data.** Every template's gated steps are editable, so
   the disabled-Edit tests and PLAN-08 make `store.can_edit` return False for that test only.
4. **Cosmetic:** the same cut row was once one character shorter on a second visit (likely a
   layout-width timing difference). It never overflows; the overflow test checks every row.

### Evidence

Committed (six key screenshots, checked: no secrets or tokens, no IP addresses; the only host
is the reserved `staging.example.com`):

- [plan-ready.svg](test-evidence/plan-ready.svg) · [plan-running.svg](test-evidence/plan-running.svg) · [plan-finished.svg](test-evidence/plan-finished.svg)
- [plan-stopped-mid-plan.svg](test-evidence/plan-stopped-mid-plan.svg) · [plan-edit-disabled.svg](test-evidence/plan-edit-disabled.svg) · [plan-layout-80x24.svg](test-evidence/plan-layout-80x24.svg)

Local only (`../test-results/plan/`, gitignored): all 11 evidence SVGs, `results.json`,
`plan-tests.log`, `full-suite.log`. The SVGs link to a web font on `cdnjs.cloudflare.com`,
fetched only when an SVG is opened directly in a browser.

### Not run

| Area | Status | Why |
|---|---|---|
| Browser tests (Playwright) | NOT RUN | Native terminal app |
| Backend security tests | NOT RUN | The TUI uses static data; it doesn't call the Core API yet |
| Manual check in a real terminal | NOT RUN | All checks ran headless through Pilot |

### Remaining risks

1. Until `terminal/input-validation` merges, holding Enter on scope approval can run the plan.
2. After it merges, holding Enter longer than 0.5 s can still reach a gate menu (terminals send
   no key-up).
3. The TUI's checks are for the person using it; the backend's scope and approval checks stay
   the authority once the API is wired.
