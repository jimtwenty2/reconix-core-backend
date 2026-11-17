# TUI Streaming Typewriter Animation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

This plan details the addition of a simulated streaming / typewriter animation for static and AI messages in the Reconix TUI (`apps/tui`), giving them the progressive reveal feel of an AI model while maintaining instant completion in test and headless environments.

---

## File Structure

- **New File:** `apps/tui/reconix/widgets/stream_text.py`
  - Defines `StreamLine(Static)`: a widget that progressively reveals text word-by-word (or in small character chunks) using Textual's `set_interval`.
  - Supports `flush()` to instantly reveal the full text.
  - Automatically bypasses animation in test/headless environments (`app.is_headless`, `os.environ.get("PYTEST_CURRENT_TEST")`, or `RECONIX_ANIMATE_STREAM=0`).
  
- **Modify:** `apps/tui/reconix/widgets/step_chat.py`
  - Integrate `StreamLine` into `StepChat.add_reply` and `StepChat.show_reply`.
  - Enable streaming for static messages, step guidance, and AI responses.
  - Add flush on user input / keypress events so fast interactions are never blocked.

- **Modify:** `apps/tui/reconix/screens/start.py`
  - Update `StartScreen` to use progressive streaming when displaying the latest reply in conversation mode.
  - Flush stream when user starts typing in the `PromptBox`.

- **New Test File:** `apps/tui/tests/test_streaming_text.py`
  - Unit tests proving progressive reveal, `flush()`, chunk progression, and headless/test bypass behavior.

---

## Tasks

### Task 1: Create `StreamLine` Widget and Typewriter Engine

- [ ] Write unit tests for `StreamLine` in `apps/tui/tests/test_streaming_text.py`:
  - Test immediate full text reveal when headless / under pytest.
  - Test progressive chunking when animated mode is forced.
  - Test `flush()` immediately reveals full text and cancels timer.
- [ ] Implement `apps/tui/reconix/widgets/stream_text.py`:
  - `StreamLine` subclass of `Static`.
  - Configuration: interval `0.02s` (20ms), 1-2 words per tick.
  - Check for test/headless environment to skip animation synchronously.
- [ ] Verify unit tests pass:
  - Run `uv run --package reconix-tui pytest apps/tui/tests/test_streaming_text.py`.

### Task 2: Integrate Streaming Animation into `StepChat`

- [ ] Write integration test in `apps/tui/tests/test_step_chat_ui.py`:
  - Prove `add_reply` and `show_reply` render correct Rich text and speaker tags.
  - Prove fast input/escape flushes any pending stream without hanging.
- [ ] Update `apps/tui/reconix/widgets/step_chat.py`:
  - Update `StepChat.add_reply` and `StepChat.show_reply` to utilize streaming.
  - Hook key events on `_ChatInput` and `ChatBar` to call `flush()` on active streaming replies.
- [ ] Verify tests pass:
  - Run `uv run --package reconix-tui pytest apps/tui/tests/test_step_chat_ui.py`.

### Task 3: Integrate Streaming Animation into `StartScreen`

- [ ] Update `StartScreen` in `apps/tui/reconix/screens/start.py`:
  - In `refresh_live()`, if a new reply is received, stream it into `#start-reply`.
  - In `on_prompt_box_submitted` and input typing handlers, flush active stream.
- [ ] Run `apps/tui/tests/test_start_screen.py` and `apps/tui/tests/test_chat_after_run_ui.py`.

### Task 4: Full Verification and Linting

- [ ] Run full workspace lint and format check:
  - `uv run ruff check apps/tui && uv run ruff format --check apps/tui`.
- [ ] Run targeted and full TUI test suite:
  - `uv run --package reconix-tui pytest apps/tui/tests/test_streaming_text.py apps/tui/tests/test_step_chat_ui.py apps/tui/tests/test_start_screen.py`.
