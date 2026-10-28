# Test report: Reconix TUI

One report for the TUI's test runs. Each run is appended under **Run history** with its own
date; earlier runs are never rewritten.

---

## Run history

### Run 1 — 2026-10-27 14:40 (UTC+7): Start screen terminal input validation

**Project:** Reconix TUI (`apps/tui`, package `reconix-tui` 0.4.0)
**Feature under test:** validation and keyboard handling of the Start screen's terminal input
**Branch / commit:** `vanhonghorn/terminal-input-validation` on `379f244`, with this feature's
changes uncommitted at run time
**Final acceptance status:** **PASS, with the exceptions listed under Not run and Remaining
risks** (no browser or backend tests apply yet; 20 failures and 4 errors in the full suite are
outside this feature and also fail without it)

> **Superseded by Run 2.** A rerun of TUI-13 later failed: the BUG-1 fix below judged keys by
> when they were handled, so it depended on machine speed, and `pilot.press()` couldn't model
> a fast double tap. Run 2 records the corrected fix, a third bug (duplicate submission) and
> the final results. This run is kept as it was.

#### Environment

| Item | Value |
|---|---|
| OS | Windows 10 Pro 10.0.19045 |
| Python | 3.12.10 (`apps/tui/.venv`) |
| UI framework | Textual 8.2.8 |
| Test runner | pytest 9.1.1, pytest-asyncio 1.4.1 |
| Lint | ruff 0.17.3 |
| Browser | None. The Start screen is a native terminal app, so Playwright can't drive it (see below). |
| Terminal driver | Textual `App.run_test()` / Pilot (headless; real key presses into the real app) |

**Why not Playwright.** The Start screen (logo, flow rail, instructions, input) is the Textual
TUI in `apps/tui/reconix/screens/start.py`. The web app (`apps/web`) has no Start screen: it is a
read-only dashboard, unchanged here. Running the TUI in a browser would need `textual-serve`, a
new dependency, for a fragile setup. Textual's Pilot sends the same key events a terminal does,
to the real app, and saves the rendered terminal as SVG, so it is used instead.

#### Objectives

1. Empty and whitespace-only input never start an assessment.
2. Slash commands are checked against the command registry (did-you-mean, usage lines).
3. Suggestions open on `/` and work with ↑/↓, Tab, Enter and Esc.
4. URLs, IPv4 addresses, CIDR and dash ranges, git repos and local folders are validated, with
   clear one-line errors and no network access.
5. Invalid input never advances the workflow; a valid target only starts the run, which stops
   at its first gate. Repeated Enter never submits twice or decides a gate.
6. A new target never reuses an earlier scope or approval.
7. Typed text is never run as a command or rendered as markup.
8. The layout holds at 80×24 and 160×50.

#### Test suites run

| Suite | Kind | Result | Evidence |
|---|---|---|---|
| `tests/test_target_validation.py` | Unit | 66 passed | `../test-results/start-input/start-input-tests.log` |
| `tests/test_command_check.py` | Unit | 27 passed | same log |
| `tests/test_start_input_ui.py` | Integration (Pilot, real app) | 58 passed | same log |
| `scripts/capture_start_input_evidence.py` | End-to-end (Pilot, real app, screenshots) | 15 of 15 passed | `../test-results/start-input/results.json` and SVGs |
| Input-related existing suites (12 files) | Unit + integration | 295 passed (baseline, before the fixes below) | console output at run time (not saved) |
| Full TUI suite | All | 1070 passed, 27 skipped, 20 failed, 4 errors | `../test-results/start-input/full-suite.log` |
| `ruff check .` | Lint | passed | console output at run time |

Paths starting with `../test-results/` are on the tester's machine only (the folder is
gitignored). The six key screenshots are committed in `test-evidence/`.

#### End-to-end cases (real app, real keys)

Screen size 140×45 unless stated. The run plays instantly (`RunController.SPEED = 0`) so gates
arrive at once; menus keep their real 0.5 s arm delay.

| ID | Scenario | Input | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|
| TUI-01 | Empty input | Enter on empty prompt | Nothing starts; hint shown | Stayed on Start, no run, hint "Type a target, a question, or / for commands." | PASS | [01-empty-input.svg](test-evidence/01-empty-input.svg) |
| TUI-02 | Whitespace only | `   \t  ` | Nothing starts; hint shown | Same as TUI-01 | PASS | `../test-results/start-input/tui-02.svg` |
| TUI-03 | Unknown command | `/plna` | Error with did-you-mean | `Unknown command "/plna". Did you mean /plan? Type / to see all commands.` | PASS | [02-unknown-command.svg](test-evidence/02-unknown-command.svg) |
| TUI-04 | Known command, bad argument | `/plan now` | Usage line | `/plan takes no argument. Usage: /plan` | PASS | `../test-results/start-input/tui-04.svg` |
| TUI-05 | Suggestions on `/` | `/` | List opens | List open with all 19 commands | PASS | [03-suggestions.svg](test-evidence/03-suggestions.svg) |
| TUI-06 | Filter, ↓, Tab | `/find`, ↓, Tab | Highlight moves; Tab completes | Highlight on `finding`; Tab gave `/finding ` | PASS | `../test-results/start-input/tui-06.svg` |
| TUI-07 | Esc order | `/f`, Esc ×3 | Close list, clear, then nothing | List closed with `/f` kept; cleared; still on Start | PASS | `../test-results/start-input/tui-07.svg` |
| TUI-08 | Invalid IPv4 | `256.0.0.1` | Error; nothing starts | `256.0.0.1 isn't a valid IPv4 address — four numbers from 0 to 255.` | PASS | [04-invalid-target.svg](test-evidence/04-invalid-target.svg) |
| TUI-09 | Unsupported scheme | `file:///etc/passwd` | Error; nothing starts | `file: links aren't supported — use http:// or https://, e.g. https://app.example.com` | PASS | `../test-results/start-input/tui-09.svg` |
| TUI-10 | Dash range | `10.0.0.1-20` | Asks for CIDR | `Dash ranges aren't supported by the scope yet — use CIDR, e.g. 10.0.0.0/27.` | PASS | `../test-results/start-input/tui-10.svg` |
| TUI-11 | Very long input | `a` × 600 | Length error; nothing starts | `That line has 600 characters — keep it under 500 …` | PASS | `../test-results/start-input/tui-11.svg` |
| TUI-12 | Shell metacharacters | `; rm -rf /` | Chat line; nothing runs or starts | Answered as chat; no run, no error | PASS | `../test-results/start-input/tui-12.svg` |
| TUI-13 | Valid target, Enter ×3 | `https://app.example.com` | Stops at scope gate; nothing approved; one request | Template screen, gate `scope`, scope/plan/approvals = none, 1 request | PASS | [05-valid-target-gate.svg](test-evidence/05-valid-target-gate.svg) |
| TUI-14 | Layout 80×24 | `/` | Logo, rail, input, list on screen | logo (11,3,54,6), rail (0,1,80,1), input (4,19,72,3), list (4,11,72,8) | PASS | [06-layout-80x24.svg](test-evidence/06-layout-80x24.svg) |
| TUI-15 | Layout 160×50 | `/` | Same | All four inside the screen | PASS | `../test-results/start-input/tui-15.svg` |

#### Automated regression tests (Pilot integration, `tests/test_start_input_ui.py`)

All PASS in `../test-results/start-input/start-input-tests.log`.

| Test | Cases | Checks |
|---|---|---|
| `test_an_empty_line_does_nothing` | 3 | `""`, `" "`, tabs: no run, no assessment, no request, hint shown |
| `test_enter_outside_the_prompt_starts_nothing` | 1 | Screen-level Enter starts nothing before a run |
| `test_during_a_run_an_empty_line_reopens_the_waiting_gate` | 1 | Navigation only; nothing decided |
| `test_an_unknown_command_explains_and_keeps_the_text` | 1 | Did-you-mean message; text kept |
| `test_the_error_clears_on_the_next_keystroke` | 1 | Error gone after one key |
| `test_a_wrong_argument_shows_the_usage` / `test_a_bad_choice_shows_the_usage_and_choices` | 2 | Usage lines |
| `test_a_valid_command_runs_in_any_case` | 1 | `  /FINDINGS ` opens Findings |
| `test_markup_in_a_typed_command_is_shown_literally` / `test_markup_in_a_rejected_target_is_shown_literally` | 2 | `[red]`, `[bold]` shown as text |
| Suggestion tests (bare `/`, ↑/↓ then Enter, filter, Tab, Esc order, hide, history) | 7 | Keyboard behaviour |
| `test_an_invalid_target_is_explained_and_nothing_starts` | 6 | `http://`, `256.0.0.1`, backwards range, `file://`, missing folder, `/8` |
| `test_a_dash_range_asks_for_cidr` / `test_a_sentence_is_still_chat` | 2 | |
| `test_a_valid_target_stops_at_the_first_gate` | 5 | URL, IPv4, CIDR, git repo → scope gate; bare host → template gate |
| `test_no_command_or_jump_decides_a_gate` | 1 | `/approval`, `/status`, `/plan`, jumps, Enter on Approval decide nothing |
| `test_a_second_target_does_not_skip_the_waiting_gate` | 1 | |
| `test_a_repeated_enter_submits_once_and_decides_no_gate` | 1 | **Regression for BUG-1** (real 0.5 s arm delay) |
| `test_a_deliberate_enter_after_the_delay_still_decides` | 1 | The guard doesn't block a real decision |
| `test_a_repeated_enter_on_an_invalid_target_changes_nothing` | 1 | |
| `test_special_characters_are_text_never_commands` | 8 | `; rm -rf /`, `$(whoami)`, backticks, `<script>`, markup, ANSI escapes, Unicode/emoji, SQL-style; process calls patched to fail |
| `test_shell_syntax_around_a_target_is_ignored_and_the_scope_waits` | 2 | `&& curl https://evil.example`, `\| nc 192.0.2.1 4444` start a run on the named target and stop at the scope gate; nothing runs |
| `test_a_line_over_the_limit_is_refused_inline` / `test_a_line_at_the_limit_is_sent` | 4 | **Regression for BUG-2** |
| `test_a_new_target_starts_from_a_fresh_scope_and_no_approvals` | 1 | After scope + an approval, `/new` + new target: fresh scope, 0 approvals |
| `test_template_after_an_approved_scope_starts_a_new_assessment` | 1 | |
| Layout tests (80×24, 160×50, long error, logo) | 5 | Rail, input, list, hint inside the screen |

Unit tests: `test_target_validation.py` (66: at least 3 valid and 3 invalid cases per target kind,
including `" "`, `http://`, `10.0.0.5-10.0.0.1`, `256.0.0.1`, `/does/not/exist`,
`file:///etc/passwd`) and `test_command_check.py` (27: valid, unknown with suggestion, bad
arguments, case and whitespace, usage lines).

#### Bugs found and fixed

| ID | Bug | Found by | Fix | Retest |
|---|---|---|---|---|
| BUG-1 | **Repeated Enter could decide gates.** Three quick Enters after a valid target submitted it, then approved the scope, then ran the plan (when the run reached its gates instantly). At normal speed the prompt's lock hid it, but a held Enter could still reach a gate menu. | Exploratory Pilot run before writing the test | Gate menus (`widgets/choice_menu.py`) ignore picks for 0.5 s after they appear or their choices change. The command-suggestion menu opts out. Tests turn the delay off globally (`tests/conftest.py`) and on in the regression tests. | TUI-13 PASS; `test_a_repeated_enter_submits_once_and_decides_no_gate` PASS; `test_a_deliberate_enter_after_the_delay_still_decides` PASS; full suite shows no new failures |
| BUG-2 | Input over 500 characters was refused only by a pop-up from the store, not the inline error. | Inspection, then Pilot test | `screens/start.py` checks the store's `MAX_REQUEST_LENGTH` inline; the store still enforces it. | TUI-11 PASS; 4 regression cases PASS |

Earlier on this branch (same feature, before this run): empty Enter started the demo
assessment, and command errors were pop-ups with no did-you-mean or usage. Both are fixed and
covered above.

#### Full-suite failures (not caused by this feature)

The full run had 20 failures and 4 errors. Each was checked against the code without this
feature's changes:

- **19 failures + 4 errors, Windows only:** 0600 file permissions, symlinks (`WinError 1314`)
  and FIFO checks in `test_knowledge_cli.py`, `test_knowledge_store.py`,
  `test_llm_providers.py`, `test_openapi.py`, `test_persist.py`, `test_web_dashboard.py`, and
  setup errors in `test_yaml_safe.py`. The same 19 + 4 fail on the unchanged code.
- **1 flaky:** `test_execution_screen.py::test_scrolling_up_stops_following_until_end`. Run 6
  times alone: 2 failed with this feature, 3 failed without it.

#### Not run or blocked

| Area | Status | Why |
|---|---|---|
| Browser tests (Playwright) | NOT RUN | The Start screen is a native terminal app; the web app has no Start screen and wasn't changed. |
| Backend security tests (scope check, approvals over the API) | NOT RUN | The apps use static data only; the TUI doesn't call the Core API yet. |
| Manual check in a real terminal (Windows Terminal) | NOT RUN | All UI checks ran headless through Pilot. |
| Browser console errors | NOT RUN | No browser involved. |

#### Remaining risks

1. **Holding Enter for longer than 0.5 s** can still reach a gate menu (terminals don't send
   key-up events). The person is still pressing Enter on the gate, but not deliberately.
2. The 0.5 s guard also applies to mouse clicks on gate menus.
3. A sentence that names a target (`&& curl https://evil.example`) starts a run on that target.
   Nothing runs, and the scope still needs approval, but the run starts.
4. **HIGH approvals use a Yes/No double check** (single-use token + command hash), not a typed
   target as `AGENTS.md` asks. Unchanged here.
5. Validation in the TUI is feedback only; the backend's scope check must stay the authority
   once the API is wired.
6. At 80×24 the welcome block was already taller than its space before this feature (the
   "No active scope" line is cut off); with a three-line error the quickstart panel loses two
   more lines. Logo, rail, input and suggestions stay visible.
7. The SVG screenshots link to a web font on `cdnjs.cloudflare.com`; a browser fetches it when
   an SVG is opened directly.

---

### Run 2 — 2026-10-27 15:14 (UTC+7): Start screen input validation, retest after fixes

**Project / feature:** Reconix TUI (`apps/tui`, `reconix-tui` 0.4.0), Start screen terminal input
**Branch / commit:** `vanhonghorn/terminal-input-validation` on `379f244`, changes uncommitted
**Environment:** as Run 1 (Windows 10 Pro 10.0.19045, Python 3.12.10, Textual 8.2.8,
pytest 9.1.1, ruff 0.17.3, headless Textual Pilot; no browser), plus a manual check in the VS
Code integrated terminal
**Final acceptance status:** **PASS, with the exceptions under Not run and Remaining risks.**
All feature tests pass; the full suite's 19 failures and 4 errors are the Windows-only baseline
that also fails without this feature.

#### What changed since Run 1

- **BUG-1 fix corrected:** gate menus now judge Enter and digit keys by when they were
  *pressed* (Textual's event timestamp), not when they are handled.
- **BUG-3 found and fixed:** one burst of Enter submitted the same line several times.
- Tests send real key bursts through the driver (`burst_of_enters`) instead of
  `pilot.press()`, which waits for the app between keys and so can't model a double tap.
- New test `test_enter_pressed_as_a_gate_appears_decides_nothing` covers the gate guard alone.
- The "Supported: …" message now lists "a CIDR range (10.0.0.0/24)" instead of advertising dash
  ranges, which the Start screen refuses.

#### Test suites run

| Suite | Kind | Result | Evidence |
|---|---|---|---|
| `tests/test_target_validation.py` | Unit | 66 passed | `../test-results/start-input/start-input-tests.log` |
| `tests/test_command_check.py` | Unit | 27 passed | same log |
| `tests/test_start_input_ui.py` | Integration (Pilot, real app) | 59 passed | same log |
| Three suites above, after the "CIDR range" text change | Unit + integration | 152 passed | same log (final run) |
| `scripts/capture_start_input_evidence.py` | End-to-end (Pilot, real app, screenshots) | 15 of 15 passed, three runs in a row | `../test-results/start-input/results.json` and SVGs |
| Full TUI suite | All | 1072 passed, 27 skipped, 19 failed, 4 errors | `../test-results/start-input/full-suite.log` |
| `ruff check .` | Lint | passed | console output at run time |
| Manual check, VS Code terminal | Manual (real terminal) | PASS (run by the tester) | tester's report, no screenshot |

The full suite started just before the one-line "CIDR range" text change; the three focused
suites were rerun after it (152 passed).

#### End-to-end cases

TUI-01 to TUI-12, TUI-14 and TUI-15 as in Run 1, all PASS again on the final code. Changed:

| ID | Scenario | Input | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|
| TUI-13 | Valid target, burst of 3 Enters | `https://app.example.com` | Stops at the scope gate; nothing approved; one request | Template screen, gate `scope`, scope/plan/approvals = none, 1 request (three runs) | PASS | [05-valid-target-gate.svg](test-evidence/05-valid-target-gate.svg) |

#### Manual check (real terminal)

| ID | Scenario | Input | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|
| MAN-01 | Unknown and mistyped commands, invalid IPv4, dash range, valid URL in the VS Code terminal | `/scna`, `/plna`, `999.1.1.1`, `10.0.0.1-20`, a valid URL | Errors explain each; the URL stops at the scope gate | As expected, reported by the tester | PASS | Tester's manual run (no screenshot) |

Note: `/scna` gets no "Did you mean" because Reconix has no `/scan` command; `/plna` suggests
`/plan`.

#### Bugs found and fixed

| ID | Bug | Fix | Retest |
|---|---|---|---|
| BUG-1 (revised) | Repeated Enter could decide gates (approve the scope, run the plan). Run 1's fix judged keys by handling time, so a key pressed early but handled after a slow screen switch still got through. | `widgets/choice_menu.py`: Enter and digit keys pressed before the menu is armed (0.5 s after it appears or its choices change) are refused, judged by the key's own timestamp; clicks keep the handling-time check. | `test_enter_pressed_as_a_gate_appears_decides_nothing` PASS (3 of 3); with the guard off it fails (the run reaches the plan gate). |
| BUG-2 | Over-long input refused only by a pop-up. | Inline check in `screens/start.py` (unchanged since Run 1). | 4 regression cases PASS. |
| BUG-3 | **Duplicate submission.** A burst of Enter on the Start prompt submitted the line once per press before the first submission cleared the box: one target recorded 3 requests (the 2nd and 3rd went into the new run as chat lines). | `widgets/prompt.py`: after a line is sent, the prompt ignores further Enters until its screen answers: it clears the box (sent), shows an error or hint, or calls the new `release()` (refused with a pop-up). Typing also releases it. `screens/start.py` calls `release()` when the app refuses a line. | `test_a_repeated_enter_submits_once_and_decides_no_gate` PASS (5 of 5); with the guard off it fails (3 requests, not 1). TUI-13 PASS three runs in a row. |

#### Full-suite failures (not caused by this feature)

19 failures + 4 errors, the same Windows-only set as Run 1 (0600 permissions, symlinks,
FIFOs, `test_yaml_safe.py` setup errors); they also fail on the unchanged code. The flaky
`test_execution_screen.py::test_scrolling_up_stops_following_until_end` passed this run.

#### Not run or blocked

| Area | Status | Why |
|---|---|---|
| Browser tests (Playwright) | NOT RUN | The Start screen is a native terminal app; the web app has no Start screen and wasn't changed. |
| Backend security tests | NOT RUN | The apps use static data only; the TUI doesn't call the Core API yet. |
| Browser console errors | NOT RUN | No browser involved. |

#### Remaining risks

1. Holding Enter for longer than 0.5 s can still reach a gate menu (terminals send no key-up).
2. The 0.5 s guard also delays mouse clicks on gate menus.
3. A sentence naming a target (`&& curl https://evil.example`) starts a run on it; nothing
   runs and the scope still needs approval.
4. HIGH approvals use a Yes/No double check (token + command hash), not a typed target as
   `AGENTS.md` asks. Unchanged.
5. TUI validation is feedback only; the backend's scope check must stay the authority once the
   API is wired.
6. At 80×24 the welcome block was already clipped before this feature; a three-line error
   hides two more lines of the quickstart panel. Logo, rail, input and suggestions stay visible.
7. The manual check has no saved screenshot; it rests on the tester's report.
