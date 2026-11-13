"""/provider and /model: configure LLM providers and pick the active model.

Handlers in `commands/builtin.py` call these methods only. Reachability tests and the chat
reply block on the network, so they run in a Textual worker thread (copying `web.py`).
Nothing here decides a gate or changes scope — a model is only ever configured or displayed.
"""

from typing import Optional

from .. import store
from ..models import Choice
from ..screens import ChoiceScreen
from ..screens.forms import ProviderForm

_VERBS = {"set", "update", "test", "unset"}


def _setup_hint(view) -> str:
    """What the set-up form asks for this provider."""
    parts = []
    if view.shows_key_field:
        parts.append("API key" + ("" if view.needs_key else " (optional)"))
    if view.shows_base_field:
        parts.append("base URL")
    if view.shows_models_field:
        parts.append("model(s)" if view.multi_model else "model")
    if not parts:
        return "Its settings"
    return parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} and {parts[-1]}"


class LlmMixin:
    """Mixed into ReconixApp."""

    # At start, while no model is active, ask which provider to use (tests switch it off).
    ASK_PROVIDER_ON_START = True
    # At the scope step, the AI reads the operator's goal and suggests tools (off in tests).
    SUGGEST_SCOPE_ON_REVIEW = True

    # --- start-up: "Set an AI provider?" ------------------------------------------------------
    def ask_provider_on_start(self) -> None:
        """Offer to set a model of your own, until one is active. Without one the Core API
        has no model and refuses (503 NO_ACTIVE_PROVIDER) until you choose: Reconix never
        picks one for you."""
        if not self.ASK_PROVIDER_ON_START or store.active_model() is not None:
            return
        choices = [
            Choice(
                "provider",
                "Set a provider…",
                "OpenAI, Anthropic, DeepSeek, Ollama or a custom endpoint (/provider)",
            ),
            Choice(
                "skip",
                "Use the Core API's model",
                "The model set in .env (RECONIX_MODEL_*). /provider changes it later.",
                recommended=True,
                separated=True,
            ),
        ]
        self.open_dialog(
            ChoiceScreen(
                "◆ SET AN AI PROVIDER",
                "Which AI model should Reconix use?",
                choices,
                chip="Provider",
            ),
            self._start_provider_chosen,
        )

    def _start_provider_chosen(self, choice: Optional[str]) -> None:
        if choice == "provider":
            self.open_provider_menu()

    # --- /provider ----------------------------------------------------------------------------
    def provider_command(self, arg: Optional[str]) -> None:
        arg = (arg or "").strip()
        if not arg:
            self.open_provider_menu()
            return
        parts = arg.split(None, 1)
        verb = parts[0].lower()
        rest = parts[1].strip().lower() if len(parts) > 1 else ""
        if verb in _VERBS:
            if not self._known(rest):
                return
            if verb in ("set", "update"):
                self.open_provider_form(rest)
            elif verb == "test":
                self.test_provider_async(rest)
            else:
                self.confirm_unset(rest)
            return
        if self._known(arg.lower()):
            self.open_provider_submenu(arg.lower())

    def _known(self, provider_id: str) -> bool:
        try:
            store.get_provider(provider_id)
            return True
        except store.StoreValidationError as exc:
            self._warn(exc)
            return False

    def open_provider_menu(self) -> None:
        """Every provider; the ACTIVE one (else the first configured) is highlighted, so it
        is on screen even when the list is longer than a small terminal (QA-002)."""
        try:
            providers = store.list_providers()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        choices = []
        default = next(
            (i for i, p in enumerate(providers) if p.active_model),
            next((i for i, p in enumerate(providers) if p.configured), 0),
        )
        for p in providers:
            tag = "ACTIVE" if p.active_model else ""
            bits = [p.status.title()]
            if p.configured and p.api_key_hint:
                bits.append(p.api_key_hint)
            if p.models:
                bits.append(", ".join(p.models))
            label = p.label + ("  [configured]" if p.configured else "")
            choices.append(Choice(p.id, label, " · ".join(bits), tag=tag))
        self.open_dialog(
            ChoiceScreen(
                "◆ LLM PROVIDERS",
                "Pick a provider to set up or manage:",
                choices,
                default=default,
                chip="Providers",
            ),
            self._provider_picked,
        )

    def _provider_picked(self, provider_id: Optional[str]) -> None:
        if provider_id:
            self.open_provider_submenu(provider_id)

    def open_provider_submenu(self, provider_id: str) -> None:
        try:
            p = store.get_provider(provider_id)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        if p.built_in:
            # The Core API's own model (RECONIX_MODEL_* in its .env): shown, never edited here.
            choices = [
                Choice(
                    "model",
                    "Use this model",
                    "Make the Core API's model the active choice",
                    disabled=not p.models,
                    reason="the Core API has no model set",
                ),
            ]
            self.open_dialog(
                ChoiceScreen(
                    f"◆ {p.label.upper()}",
                    f"{p.label} · the Core API's own model",
                    choices,
                    chip="Provider",
                ),
                lambda choice: self._submenu_chosen(provider_id, choice),
            )
            return
        setup = "Update" if p.configured else "Set up"
        if not p.configured:
            use_reason = "set up first"
        elif not p.reachable:
            use_reason = "test first"
        else:
            use_reason = "no model listed"
        choices = [
            Choice("set", f"{setup} {p.label}", _setup_hint(p)),
            Choice(
                "test",
                "Test connection",
                "Check the key and that the model is reachable",
                disabled=not p.configured,
                reason="set up first",
            ),
            Choice(
                "model",
                "Use a model",
                "Make one of its models the active choice",
                disabled=not (p.reachable and p.models),
                reason=use_reason,
            ),
            Choice(
                "unset",
                "Unset",
                "Remove this provider",
                disabled=not p.configured,
                separated=True,
                reason="not set up",
            ),
        ]
        self.open_dialog(
            ChoiceScreen(
                f"◆ {p.label.upper()}", f"{p.label} · {p.status.title()}", choices, chip="Provider"
            ),
            lambda choice: self._submenu_chosen(provider_id, choice),
        )

    def _submenu_chosen(self, provider_id: str, choice: Optional[str]) -> None:
        if choice == "set":
            self.open_provider_form(provider_id)
        elif choice == "test":
            self.test_provider_async(provider_id)
        elif choice == "model":
            self.open_model_menu(provider_id)
        elif choice == "unset":
            self.confirm_unset(provider_id)

    def open_provider_form(self, provider_id: str) -> None:
        try:
            form = ProviderForm(provider_id)  # the form reads the provider in its constructor
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.open_dialog(form, lambda result: self._provider_saved(provider_id, result))

    def _provider_saved(self, provider_id: str, result: Optional[str]) -> None:
        self.refresh_view()
        if result != "saved":
            return
        try:
            label = store.get_provider(provider_id).label
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.open_dialog(
            ChoiceScreen(
                "✓ PROVIDER SAVED",
                f"Saved {label}. Test the connection now?",
                [Choice("test", "Yes, test it now"), Choice("later", "Not now")],
                chip="Provider",
            ),
            lambda choice: self.test_provider_async(provider_id) if choice == "test" else None,
        )

    # --- test (worker) ------------------------------------------------------------------------
    def test_provider_async(self, provider_id: str) -> None:
        try:
            view = store.get_provider(provider_id)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        if not view.configured:
            self.notify(f"{view.label} is not configured yet.", severity="warning", markup=False)
            return
        self.notify(f"Testing {view.label}…", markup=False)
        self.run_worker(
            lambda: self._run_test(provider_id), thread=True, group="llm", exit_on_error=False
        )

    def _run_test(self, provider_id: str) -> None:
        try:
            view = store.test_provider(provider_id)
        except store.StoreValidationError as exc:
            self.from_worker(self._warn, exc)
            return
        self.from_worker(self._test_done, view)

    def _test_done(self, view) -> None:
        """Say how the test went. A reachable provider becomes the active model when none is
        active yet; a model off this computer asks for your OK first."""
        message = f"{view.label}: {view.status} — {view.status_detail}"
        active = None
        if view.reachable and view.models and store.active_model() is None:
            try:
                active = store.activate(view.id, view.models[0])
                if store.core_api_needs_ok():
                    message += f" · Approve {active.label} · {active.model} to use it"
                else:
                    message += f" · Active model now: {active.label} · {active.model}"
            except store.StoreValidationError as exc:
                message += f" {exc}"
        self.refresh_view()
        self.notify(message, severity="information" if view.reachable else "warning", markup=False)
        if active and store.core_api_needs_ok():
            self.ask_core_api_ok(view.id, active)

    # --- unset --------------------------------------------------------------------------------
    def confirm_unset(self, provider_id: str) -> None:
        try:
            view = store.get_provider(provider_id)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        if not view.configured:
            self.notify(f"{view.label} is not configured.", severity="warning", markup=False)
            return
        self.open_dialog(
            ChoiceScreen(
                f"REMOVE {view.label.upper()}?",
                f"This deletes {view.label}'s saved key and settings.",
                [Choice("keep", "No, keep it"), Choice("unset", "Yes, remove it", tone="danger")],
                chip="Provider",
                danger=True,
                default=0,
            ),
            lambda choice: self._do_unset(provider_id) if choice == "unset" else None,
        )

    def _do_unset(self, provider_id: str) -> None:
        try:
            label = store.get_provider(provider_id).label
            store.unset_provider(provider_id)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.refresh_view()
        self.notify(f"Removed {label}.", markup=False)

    # --- /model -------------------------------------------------------------------------------
    def model_command(self, arg: Optional[str]) -> None:
        arg = (arg or "").strip()
        if not arg:
            self.open_model_menu()
            return
        self.activate_model(arg)

    def open_model_menu(self, only_provider: Optional[str] = None) -> None:
        try:
            providers = store.list_providers()
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        choices = []
        for p in providers:
            if only_provider and p.id != only_provider:
                continue
            if not p.configured or not p.models:
                continue
            for i, model in enumerate(p.models):
                active = p.active_model == model
                hint = (
                    "active"
                    if active
                    else ("ready" if p.reachable else "Test the connection first")
                )
                choices.append(
                    Choice(
                        f"{p.id}/{model}",
                        f"{p.label} · {model}",
                        hint,
                        disabled=not p.reachable,
                        separated=(i == 0),
                        tag="ACTIVE" if active else "",
                    )
                )
        if not choices:
            self.notify(
                "No models yet. Use /provider to set one up and test it.",
                severity="warning",
                markup=False,
            )
            return
        self.open_dialog(
            ChoiceScreen(
                "◆ CHOOSE A MODEL",
                "Pick the model the next chat line will use:",
                choices,
                chip="Model",
            ),
            self.activate_model,
        )

    def activate_model(self, spec: Optional[str]) -> None:
        if not spec or "/" not in spec:
            if spec:
                self.notify(
                    "Use provider/model, e.g. openai/gpt-4o-mini.", severity="warning", markup=False
                )
            return
        provider_id, model = spec.split("/", 1)
        try:
            active = store.activate(provider_id.strip(), model.strip())
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        self.refresh_view()
        self.notify(f"Active model: {active.label} · {active.model}", markup=False)
        if store.core_api_needs_ok():
            self.ask_core_api_ok(provider_id.strip(), active)

    # --- the Core API's OK for a model off this computer --------------------------------
    def ask_core_api_ok(self, provider_id: str, active) -> None:
        """A model off this computer becomes active only after you approve it: the Core
        API will send your scope, plan and chat (secrets masked) to it. No: it stays
        pending and the model active before is kept."""
        from urllib.parse import urlsplit

        from rich.text import Text

        try:
            view = store.get_provider(provider_id)
        except store.StoreValidationError as exc:
            self._warn(exc)
            return
        host = urlsplit(view.base_url).hostname if view.base_url else ""
        body = [
            Text("The Core API will send your scope, plan and chat (secrets masked) to:"),
            Text(f"  Provider  {view.label}"),
            Text(f"  Model     {active.model}"),
            Text(f"  Address   {host or 'the provider’s own API'}"),
            Text(f"  Key       {view.api_key_hint or 'none'}"),
        ]
        choices = [
            Choice("approve", "Approve", "make this the active model", recommended=True),
            Choice("cancel", "Not now", "leave it pending; keep the model active before"),
        ]
        self.open_dialog(
            ChoiceScreen(
                "◆ USE THIS MODEL IN THE CORE API?",
                "This model runs off this computer.",
                choices,
                body=body,
                chip="Approval",
            ),
            self._core_api_ok_answer,
        )

    def _core_api_ok_answer(self, answer: Optional[str]) -> None:
        if answer != "approve":
            self.notify("Not approved: the model is left pending.", markup=False)
            return
        self.notify("Approving it in the Core API…", markup=False)
        self.run_worker(self._core_api_approve, thread=True, group="llm", exit_on_error=False)

    def _core_api_approve(self) -> None:
        from ..llm import LLMError

        try:
            store.core_api_approve()
        except LLMError as exc:
            self.from_worker(self.notify, f"Core API: {exc}", severity="warning", markup=False)
            return
        self.from_worker(self.notify, "The Core API uses this model now.", markup=False)
        self.from_worker(self.refresh_view)
