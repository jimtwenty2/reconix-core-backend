"""Starting, deciding and leaving assessments: what the screens and commands ask the app to do.

Every decision goes through the store, which validates it and raises
`StoreValidationError` when it isn't allowed; the app shows that message and changes
nothing else. After a decision the run plays on (`resume_run`).
"""

from typing import Optional

from .. import store
from ..flow import screen_for
from ..models import ChatEntry, Choice
from ..screens.choice import ChoiceScreen
from ..screens.forms import ApprovalEditForm, OpenApiForm, ScopeEditForm


class ActionsMixin:
    """Mixed into ReconixApp."""

    # Which assessment the chat workers are answering for. `leave_assessment()` bumps it, so
    # a model reply that arrives after a switch or a /new is dropped instead of being written
    # into the run now on screen.
    _llm_gen = 0

    def _warn(self, exc: Exception) -> None:
        self.notify(str(exc), severity="warning", markup=False)

    def _remember(self, text: str) -> None:
        try:
            store.add_history(text)
        except store.StoreValidationError:
            pass  # history is best-effort; the action itself already succeeded

    # --- the start prompt --------------------------------------------------------------------
    def submit_request(self, text: str) -> bool:
        """A line typed at the Start prompt. True when it was accepted (the prompt clears).

        Before a run, a target starts the run, anything else gets a short answer (the
        active model's, when one is set) and an empty line does nothing (returns False).
        During a run the line goes to the assistant;
        an empty line reopens what the run waits for. After the run has finished
        (completed or stopped) every line is still a chat turn about that same assessment,
        with its history and context; an empty line opens Findings (or Report when there are
        none). A new assessment starts only with /new or /template.
        """
        text = text.strip()
        run = store.get_run()
        if run.started:
            if not text:
                if store.is_finished():
                    self.goto("findings" if store.list_findings() else "report")
                else:
                    self.goto(self.resume_screen_name())
                return True
            try:
                answer = store.say_operator_line(text)
            except store.StoreValidationError as exc:
                self._warn(exc)
                return False
            self._remember(text)
            self.refresh_view()  # the operator line shows at once
            # The Core API's AI answers off the UI thread while the run keeps playing.
            self._ask_model(answer)
            return True
        if not text:
            return False  # nothing typed: no run starts, nothing changes
        try:
            result = store.submit_prompt(text)
        except (store.StoreValidationError, ValueError) as exc:
            # ValueError: a backstop, so a line the parser can't read never ends the app
            self._warn(exc)
            return False
        self._remember(text)
        self.refresh_view()
        if result == "started":
            self.controller.resume()
        elif result == "ask":  # no target, a model active: the model answers
            self.notify("Thinking…", timeout=2)
            self._ask_model(store.recorded_line(text))  # the model gets the masked line only
        return True

    def _ask_model(self, line: str) -> None:
        """Ask the model about `line` in a worker: a "thinking…" line shows at once, the
        reply grows in it while the model writes, and it is recorded only on this run."""
        gen = self._llm_gen
        placeholder = store.begin_reply()
        self.refresh_view()
        self.run_worker(
            lambda: self._llm_answer(line, gen, placeholder),
            thread=True, group="llm", exit_on_error=False,
        )

    def _llm_answer(self, text: str, gen: int, placeholder: ChatEntry) -> None:
        """Worker thread: build the model reply (its line grows on screen while the model
        writes), then record it on the UI thread."""
        draft = store.build_draft(
            text,
            on_text=lambda so_far: self.from_worker(
                self._preview_reply, placeholder, so_far, gen),
        )
        self.from_worker(self._record_llm_reply, draft, gen, placeholder)

    def _preview_reply(self, placeholder: ChatEntry, text: str, gen: int) -> None:
        """A streamed reply grew: show it in its line, only on the run it was asked in."""
        if gen != self._llm_gen:
            return
        store.preview_reply(placeholder, text)
        self._redraw_reply()

    def _record_llm_reply(self, draft: store.Draft, gen: int,
                          placeholder: Optional[ChatEntry] = None) -> None:
        """Write the reply the worker built into the assessment it was asked in, or drop it.

        Nothing is recorded when another assessment came on screen while the model was
        answering (`gen`): the reply belongs to the run the question was typed in, and
        writing it anywhere else would put one run's words in another's chat and history.
        """
        if gen != self._llm_gen:
            return
        store.record_draft(draft, placeholder)
        self.refresh_view()

    def llm_generation(self) -> int:
        """Which assessment the chat workers are answering for (see `_record_llm_reply`)."""
        return self._llm_gen

    def leave_assessment(self) -> None:
        """About to leave the current assessment (a switch or /new).

        Drops what is still in flight on the run being left: a model reply being built (and
        its unfinished "thinking…" line), and any open HIGH-risk confirmation token, so coming
        back to a HIGH gate always needs the confirmation step again.
        """
        self._llm_gen += 1  # a late model reply is dropped, not misfiled
        store.drop_pending_replies()
        self._void_confirmations()
        self.controller.stop()

    @staticmethod
    def _void_confirmations() -> None:
        """Void every live HIGH confirmation token of the current assessment."""
        for request in store.get_assessment().approvals:
            if request.risk == "HIGH" and store.decision_for(request.request_id) is None:
                store.decline_confirmation(request.request_id)

    def _redraw_reply(self) -> None:
        """A streamed reply grew: redraw the screen (no save; the final refresh saves)."""
        screen = self.flow_screen()
        if screen is not None:
            screen.refresh_view()

    # --- template and scope (the Template screen) --------------------------------------------
    def open_template(self, template_id: Optional[str] = None) -> None:
        """`/template`: the Template screen; a fresh assessment if the current one is past it."""
        run = store.get_run()
        if run.started and (store.is_scope_approved() or run.stopped):
            self.leave_assessment()
            store.new_assessment()
            self.notify("Started a new assessment. The previous one is under /assessments.")
        self.template_pick = template_id if not store.get_run().started else None
        self.goto("template")

    def start_with_template(self, text: str, template_id: str) -> None:
        """The target typed for a picked template: start the run on it."""
        if store.get_run().started:
            self.leave_assessment()
            store.new_assessment()
        try:
            store.start_run(text, template_id)
        except (store.StoreValidationError, ValueError) as exc:  # ValueError: a backstop
            self._warn(exc)
            return
        self._remember(text)
        self.resume_run()

    def choose_template(self, template_id: str) -> None:
        try:
            store.select_template(template_id)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.resume_run()

    def approve_scope(self) -> None:
        try:
            store.approve_scope()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self._draft_plan()
        self.resume_run()

    def draft_plan_again(self) -> None:
        """/plan after the AI couldn't draft the plan: ask the Core API once more."""
        if not store.get_assessment().live.agent_run_id and not store.is_plan_started():
            self._draft_plan()
            self.refresh_view()

    def redraft_plan(self, on_done=None) -> None:
        """Re-draft the plan on the Core API (a plan-change request in the step chat): the
        latest chat guidance is already with the API, so a fresh draft reflects it."""
        self._draft_plan(on_done)

    def suggest_scope(self) -> None:
        """At the Scope step, the AI reads the operator's goal and suggests tools (a worker);
        when it returns, the suggestions show in the step chat as unticked rows to approve."""
        request = store.scope_suggest_request()
        if request is None:
            return

        def work() -> None:
            from ..llm import LLMError
            try:
                reply = store.fetch_scope_suggest(request)
            except LLMError as exc:
                self.from_worker(store.scope_suggest_failed, request, str(exc))
                self.from_worker(self.refresh_view)
            else:
                self.from_worker(self._scope_suggested, request, reply)

        self.run_worker(work, thread=True, group="llm", exit_on_error=False)

    def _scope_suggested(self, request, reply) -> None:
        # The goal read landed: record it and rebuild the Scope screen. The card (its "Your
        # goal" line) and an unticked tick list of the suggested tools appear together, once;
        # only the operator's tick adds a tool. The card stays on screen (no flash).
        store.apply_scope_suggest(request, reply)
        self.refresh_view()

    def _draft_plan(self, on_done=None) -> None:
        """The AI drafts the plan on the Core API in a worker; Run plan waits for it.
        `on_done` (if given) runs on the UI thread when the draft has landed."""
        request = store.plan_draft_request()
        if request is None:
            if on_done is not None:
                on_done()
            return

        def work() -> None:
            from ..llm import LLMError
            try:
                raw = store.fetch_plan_draft(request)
            except LLMError as exc:
                self.from_worker(store.plan_draft_failed, request, str(exc))
            else:
                self.from_worker(store.apply_plan_draft, request, raw)
            self.from_worker(self.refresh_view)
            if on_done is not None:
                self.from_worker(on_done)

        self.run_worker(work, thread=True, group="llm", exit_on_error=False)

    def edit_scope(self) -> None:
        self.open_dialog(ScopeEditForm(), lambda _result: self.refresh_view())

    def attach_api_spec(self) -> None:
        """The API template's form: its base URL and an OpenAPI spec (a file or a URL on the
        API's host); the store validates and reads them."""
        self.open_dialog(OpenApiForm(), lambda _result: self.refresh_view())

    def remove_api_spec(self) -> None:
        """Detach the OpenAPI file: the template's endpoints and methods come back."""
        try:
            store.remove_api_spec()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.notify("OpenAPI spec removed.", title="OpenAPI", markup=False)
        self.refresh_view()

    # --- editing where a gated action runs ("Edit params", the plan's "Edit steps") --------
    def edit_approval(self, request_id: str) -> None:
        if not store.can_edit(request_id):
            self.notify("This action can't be edited now.", severity="warning")
            return
        self.open_dialog(ApprovalEditForm(request_id), lambda _result: self.refresh_view())

    def edit_plan_steps(self) -> None:
        """Ask which gated action to edit, then open its form."""
        choices = [
            Choice(
                request.request_id,
                request.action,
                f"{request.risk} · {request.param_label}: {request.path}",
            )
            for request in store.get_assessment().approvals
            if store.can_edit(request.request_id)
        ]
        if not choices:
            self.notify("No step can be edited now.", severity="warning")
            return
        choices.append(Choice("back", "Back to the plan", "Nothing changes."))
        dialog = ChoiceScreen(
            "✎ EDIT STEPS",
            "Which gated step do you want to change?",
            choices,
            default=len(choices) - 1,
            chip="Plan",
        )
        self.open_dialog(dialog, self._plan_step_chosen)

    def _plan_step_chosen(self, answer: Optional[str]) -> None:
        if answer and answer != "back":
            self.edit_approval(answer)

    def reject_scope(self) -> None:
        try:
            store.reject_scope()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        # Stay on this assessment (QA-003): its Template step shows it stopped, the "Scope
        # rejected" lines stay in its chat, and the Template screen asks "Start again?".
        self.controller.stop()
        self.notify("Scope rejected — nothing was tested.", title="Scope")
        self.goto("template")
        self.refresh_view()

    # --- the plan and the run ------------------------------------------------------------------
    def run_plan(self) -> None:
        try:
            store.run_plan()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.gate_decided("execution")

    def stop_run(self) -> None:
        try:
            store.stop_run()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.controller.stop()
        self.refresh_view()

    # --- assessments ----------------------------------------------------------------------------
    def new_assessment(self, target: Optional[str] = None) -> None:
        """Start over on a fresh assessment (earlier ones stay listed); optionally on `target`."""
        self.leave_assessment()  # nothing in flight may write into the new run
        created = store.new_assessment()  # False: the current one is still empty; keep it
        self.selected_finding = ""
        self.findings_filter = "all"
        self.goto("start")
        if target and target.strip():
            self.submit_request(target)
        elif not created:
            self.notify(
                "You're already on a new assessment — type a target to begin.",
                title="New assessment",
            )

    def switch_assessment(self, index: int) -> None:
        """Reopen another assessment where it stands; a run that was playing plays on."""
        self.leave_assessment()  # nothing in flight may write into the run we open
        try:
            store.switch_assessment(index)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.selected_finding = ""
        self.goto(self.resume_screen_name())
        gate = store.waiting_gate()
        if (
            store.get_run().started
            and not store.is_finished()
            and (not gate or store.gate_state(gate) != "pending")
        ):
            self.controller.resume()

    def resume_screen_name(self) -> str:
        """The screen that shows where the current assessment stands."""
        run = store.get_run()
        if not run.started:
            return "start"
        gate = store.waiting_gate()
        if gate and not store.is_finished() and store.gate_state(gate) == "pending":
            return screen_for(gate)
        return "execution" if run.plan_started else "template"

    # --- findings and chat ------------------------------------------------------------------
    def open_finding(self, fid: str) -> None:
        self.selected_finding = fid
        self.goto("detail")

    def open_chat(self, draft: str = "") -> None:
        """Leave the current question and continue in the chat prompt."""
        self.pending_prompt = draft
        self.goto("start")
