"""The terminal app (TUI) in a pseudo-terminal, for the web Terminal page.

The API starts one `reconix` process per WebSocket, on this computer, and passes the
keys in and the screen out. The command is fixed (never from settings or the page), so
this cannot start a shell or a pentest tool: tools still run only through the harness,
an approval and the MCP client.

Unix only (pty). The TUI gets its own process group, and stop() signals the whole group.
A child the TUI moves to a new session of its own (the TUI's /web dashboard does) is the
TUI's job to stop.
"""

import asyncio
import fcntl
import importlib.util
import os
import pty
import shutil
import signal
import struct
import sys
import termios
from pathlib import Path

from pydantic import AliasChoices

from reconix_api.core.config import Settings

READ_SIZE = 65536  # bytes read from the terminal at a time
QUEUE_SIZE = 64  # screen chunks waiting for the page; reading pauses when it is full
STOP_SECONDS = 3  # SIGTERM first; SIGKILL if the TUI is still running after this
WRITE_SECONDS = 5  # a paste the TUI does not read within this is dropped

# The AI Service's settings, read straight from the environment (not API settings fields).
AI_SERVICE_SETTINGS = {
    "RECONIX_MODEL_URL",
    "RECONIX_MODEL_API_KEY",
    "RECONIX_MODEL_NAME",
    "RECONIX_EMBEDDINGS_URL",
    "RECONIX_OLLAMA_URL",
    "RECONIX_QDRANT_URL",
}


def api_setting_names() -> set[str]:
    """Every environment name an API setting is read from: RECONIX_<field> and each alias,
    new and old (RECONIX_MCP_AUTH_TOKEN, RECONIX_FERNET_KEY, ...)."""
    names = set()
    for name, field in Settings.model_fields.items():
        names.add(f"RECONIX_{name.upper()}")
        alias = field.validation_alias
        choices = alias.choices if isinstance(alias, AliasChoices) else [alias]
        names |= {choice for choice in choices if isinstance(choice, str)}
    return names


# The API's own settings, as environment variables. Never handed to the TUI; the TUI's own
# RECONIX_* settings (its data folder, for example) still are.
API_SETTINGS = api_setting_names() | AI_SERVICE_SETTINGS


class TerminalAppMissing(RuntimeError):
    """The terminal app is not installed where the API can start it."""


def default_command() -> list[str]:
    """The terminal app from the API's own environment, or else the `reconix` command
    installed with `uv tool install ./apps/tui`. Neither: TerminalAppMissing.

    -I: Python ignores the working folder and PYTHON* variables, so no file in the home
    folder (a stray reconix.py, say) is loaded instead of the real app."""
    if importlib.util.find_spec("reconix") is not None:
        return [sys.executable, "-I", "-c", "from reconix.app import main; main()"]
    installed = shutil.which("reconix")
    if installed is None:
        raise TerminalAppMissing("Install the terminal app: uv tool install ./apps/tui")
    return [installed]


def child_environment(cols: int, rows: int) -> dict[str, str]:
    env = {name: value for name, value in os.environ.items() if name not in API_SETTINGS}
    env.update(TERM="xterm-256color", COLORTERM="truecolor", COLUMNS=str(cols), LINES=str(rows))
    return env


class Terminal:
    """One running TUI. start(), then read() / write() / resize(), and always stop()."""

    def __init__(self, command: list[str], cols: int, rows: int) -> None:
        self.command = command
        self.cols, self.rows = cols, rows
        self.master: int | None = None
        self.process: asyncio.subprocess.Process | None = None
        self.output: asyncio.Queue[bytes | None] = asyncio.Queue(QUEUE_SIZE)
        self.reading = False

    async def start(self) -> None:
        master, slave = pty.openpty()
        self.master = master
        self._set_size(self.cols, self.rows)
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=child_environment(self.cols, self.rows),
                cwd=Path.home(),
                start_new_session=True,  # its own process group
                close_fds=True,
            )
        except BaseException:
            os.close(master)
            self.master = None
            raise
        finally:
            os.close(slave)
        os.set_blocking(master, False)
        self._resume_reading()

    async def read(self) -> bytes | None:
        """The next screen output; None once the TUI has exited."""
        data = await self.output.get()
        self._resume_reading()  # there is room again
        return data

    async def write(self, data: bytes) -> None:
        """All of data, while the TUI keeps reading; the rest is dropped after WRITE_SECONDS,
        so a stuck TUI never keeps the page from being heard."""
        deadline = asyncio.get_running_loop().time() + WRITE_SECONDS
        while data and self.master is not None:
            try:
                data = data[os.write(self.master, data) :]
            except BlockingIOError:
                if asyncio.get_running_loop().time() > deadline:
                    return
                await asyncio.sleep(0.01)

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        self._set_size(cols, rows)

    async def stop(self) -> int | None:
        """Stops the TUI and its process group, and closes the terminal. Safe to call twice."""
        self._pause_reading()
        if self.master is not None:
            os.close(self.master)
            self.master = None
        if self.process is None:
            return None
        # Always the whole group: children may still run after the TUI itself has exited.
        self._signal(signal.SIGTERM)
        if self.process.returncode is None:
            try:
                await asyncio.wait_for(self.process.wait(), STOP_SECONDS)
            except TimeoutError:
                self._signal(signal.SIGKILL)
                await self.process.wait()
        return self.process.returncode

    def _on_readable(self) -> None:
        try:
            data = os.read(self.master, READ_SIZE) if self.master is not None else b""
        except BlockingIOError:
            return
        except OSError:  # EIO: the TUI closed its side of the terminal
            data = b""
        if not data:
            self._pause_reading()
            self.output.put_nowait(None)  # room is always kept for it, see below
            return
        self.output.put_nowait(data)
        if self.output.qsize() >= QUEUE_SIZE - 1:
            # The page is behind: stop reading until it catches up. The TUI then waits on
            # its full terminal, instead of the API keeping its output in memory.
            self._pause_reading()

    def _resume_reading(self) -> None:
        if not self.reading and self.master is not None and self.output.qsize() < QUEUE_SIZE - 1:
            asyncio.get_running_loop().add_reader(self.master, self._on_readable)
            self.reading = True

    def _pause_reading(self) -> None:
        if self.reading and self.master is not None:
            asyncio.get_running_loop().remove_reader(self.master)
        self.reading = False

    def _set_size(self, cols: int, rows: int) -> None:
        if self.master is not None:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def _signal(self, number: int) -> None:
        try:
            os.killpg(self.process.pid, number)
        except ProcessLookupError:
            pass
