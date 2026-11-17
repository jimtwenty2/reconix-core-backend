"""Installation and local-service diagnostics for Reconix."""

import os
import shutil
import socket
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from rich.align import Align
from rich.console import Console
from rich.padding import Padding
from rich.rule import Rule
from rich.text import Text

from .screens.start import LOGO

OK = "OK"
WARNING = "WARNING"
FAILED = "FAILED"

Runner = Callable[..., subprocess.CompletedProcess]
Requester = Callable[..., object]


@dataclass(frozen=True)
class Diagnostic:
    """One diagnostic result and its actionable remediation."""

    name: str
    status: str
    detail: str
    remediation: str = ""


@dataclass(frozen=True)
class DiagnosticReport:
    """The complete result of a doctor run."""

    results: Tuple[Diagnostic, ...]

    @property
    def ok(self) -> bool:
        return all(result.status == OK for result in self.results)

    def render(self, console: Console) -> None:
        """Print the report with stable, readable status badges."""
        console.print()
        console.print(Padding(Align.left(Text(LOGO, style="bold cyan")), (0, 0, 0, 2)))
        console.print(Padding(Align.left(Text("D O C T O R", style="bold white")), (0, 0, 0, 2)))
        console.print(
            Padding(
                Align.left(Text("Installation & Local Health Check", style="dim")), (0, 0, 0, 2)
            )
        )
        console.print(Padding(Rule(style="cyan"), (0, 0, 0, 2)))
        console.print()
        console.print(
            Padding(
                Text("Doctor summary (Reconix installation and health checks):", style="bold"),
                (0, 0, 0, 2),
            )
        )
        console.print()
        for result in self.results:
            badge = {"OK": "green", "WARNING": "yellow", "FAILED": "red"}[result.status]
            line = Text()
            line.append(
                {"OK": "[✓]", "WARNING": "[!]", "FAILED": "[✗]"}[result.status],
                style=badge,
            )
            line.append(f" {result.name}", style="bold")
            line.append(f" ({result.detail})")
            console.print(Padding(line, (0, 0, 0, 2)))
            if result.remediation:
                console.print(
                    Padding(Text(f"    • Fix: {result.remediation}", style="yellow"), (0, 0, 0, 2))
                )
        counts = {
            status: sum(result.status == status for result in self.results)
            for status in (OK, WARNING, FAILED)
        }
        if counts[FAILED]:
            summary = (
                f"✗ Doctor found {counts[FAILED]} failed check{'s' if counts[FAILED] != 1 else ''}"
            )
            if counts[WARNING]:
                summary += f" and {counts[WARNING]} warning"
                summary += "s" if counts[WARNING] != 1 else ""
            summary += "."
            style = "red"
        elif counts[WARNING]:
            summary = f"! Doctor found {counts[WARNING]} warning"
            summary += "s" if counts[WARNING] != 1 else ""
            summary += "."
            style = "yellow"
        else:
            summary = "✓ Doctor found no issues."
            style = "green"
        console.print()
        console.print(Padding(Text(summary, style=style), (0, 0, 0, 2)))


def _find_root(start: Optional[Path]) -> Path:
    """Find the TUI configuration directory from the current directory or package."""
    candidates: List[Path] = []
    if start is not None:
        candidates.extend((start, start / "apps" / "tui"))
    candidates.extend(
        (Path.cwd(), Path.cwd() / "apps" / "tui", Path(__file__).resolve().parents[1])
    )
    for candidate in candidates:
        if (candidate / ".env.example").is_file():
            return candidate
    return candidates[0]


def _env_keys(path: Path) -> List[str]:
    """Read assignment names from an example environment file."""
    keys: List[str] = []
    if not path.is_file():
        return keys
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key and key not in keys:
            keys.append(key)
    return keys


def _request(url: str, *, method: str = "GET", data: bytes = b"", timeout: float = 3.0) -> int:
    request = urllib.request.Request(url, data=data or None, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def _run(command: Sequence[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _check_python() -> Diagnostic:
    version = sys.version_info
    if version >= (3, 12):
        return Diagnostic("Python", OK, f"{version.major}.{version.minor}.{version.micro}")
    return Diagnostic(
        "Python",
        FAILED,
        f"{version.major}.{version.minor}.{version.micro} is too old",
        "Install Python 3.12 or newer and recreate the Reconix environment.",
    )


def _check_command(name: str, label: str, remediation: str) -> Diagnostic:
    if shutil.which(name):
        return Diagnostic(label, OK, "available on PATH")
    return Diagnostic(label, FAILED, f"{name} was not found", remediation)


def _check_env(root: Path, environ: Mapping[str, str]) -> Diagnostic:
    example = root / ".env.example"
    env_file = root / ".env"
    if not env_file.is_file():
        return Diagnostic(
            ".env",
            FAILED,
            "file does not exist",
            "Copy .env.example to .env and fill in the values.",
        )
    required = _env_keys(example)
    configured = set(_env_keys(env_file))
    missing = [key for key in required if key not in configured]
    if missing:
        return Diagnostic(
            ".env",
            FAILED,
            f"missing keys: {', '.join(missing)}",
            f"Add the missing keys from {example}.",
        )
    return Diagnostic(".env", OK, f"{len(required)} example keys are present")


def _check_http(name: str, url: str, remediation: str, requester: Requester) -> Diagnostic:
    try:
        status = int(requester(url))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return Diagnostic(name, FAILED, f"not reachable ({exc})", remediation)
    if 200 <= status < 300:
        return Diagnostic(name, OK, f"reachable (HTTP {status})")
    return Diagnostic(name, WARNING, f"returned HTTP {status}", remediation)


def _core_api_health() -> bool:
    """Use the TUI's Core API seam for the in-app health check."""
    from .core_api import client

    return client.health()


def _check_core_api_for_tui() -> Diagnostic:
    if _core_api_health():
        return Diagnostic("Core API", OK, "reachable")
    return Diagnostic(
        "Core API",
        FAILED,
        "not reachable",
        "Start the Core API with ./deploy/dev.sh.",
    )


def _database_endpoint(database_url: str) -> Optional[Tuple[str, int]]:
    if database_url.startswith("sqlite"):
        return None
    parsed = urlsplit(database_url.replace("+psycopg", "", 1))
    if not parsed.hostname:
        return None
    return parsed.hostname, parsed.port or 5432


def _check_database(root: Path, environ: Mapping[str, str], runner: Runner) -> Diagnostic:
    database_url = environ.get("RECONIX_DATABASE_URL", "").strip()
    if database_url.startswith("sqlite"):
        database_path = database_url.split("///", 1)[-1]
        if not Path(database_path).expanduser().is_file():
            return Diagnostic(
                "Database",
                FAILED,
                "SQLite database file is missing",
                "Start the Core API so it can create or migrate the database.",
            )
    else:
        endpoint = _database_endpoint(database_url or "postgresql://127.0.0.1:5432/reconix")
        if endpoint is None:
            return Diagnostic(
                "Database",
                FAILED,
                "database URL is invalid",
                "Set RECONIX_DATABASE_URL to a valid database URL.",
            )
        try:
            with socket.create_connection(endpoint, timeout=3):
                pass
        except OSError as exc:
            return Diagnostic(
                "Database",
                FAILED,
                f"{endpoint[0]}:{endpoint[1]} is unreachable ({exc})",
                "Start PostgreSQL and verify RECONIX_DATABASE_URL.",
            )

    alembic = root.parent.parent / "services" / "api" / "alembic.ini"
    if not alembic.is_file():
        return Diagnostic(
            "Database migrations",
            WARNING,
            "API migration files are not in this checkout",
            "Run this command from the Reconix repository checkout.",
        )
    try:
        result = runner(
            ["uv", "run", "--package", "reconix-api", "alembic", "-c", str(alembic), "check"],
            cwd=root.parent.parent,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return Diagnostic(
            "Database migrations",
            FAILED,
            f"Alembic could not run ({exc})",
            "Install the API dependencies and run alembic upgrade head.",
        )
    if result.returncode == 0:
        return Diagnostic("Database migrations", OK, "Alembic reports no pending migrations")
    output = (result.stdout or result.stderr or "").strip().splitlines()
    detail = output[-1] if output else "Alembic migration check failed"
    return Diagnostic(
        "Database migrations",
        FAILED,
        detail,
        "Run the API migration command: alembic upgrade head.",
    )


def _check_mcp(name: str, url: str, requester: Requester) -> Diagnostic:
    payload = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    return _check_http(
        name,
        url,
        "Start the Kali MCP container and check RECONIX_KALI_MCP_URL.",
        lambda target: requester(target, method="POST", data=payload),
    )


def _check_docker(runner: Runner) -> Diagnostic:
    if not shutil.which("docker"):
        return Diagnostic(
            "Docker daemon", FAILED, "docker was not found", "Install Docker and start its daemon."
        )
    try:
        result = runner(["docker", "info"])
    except (OSError, subprocess.SubprocessError) as exc:
        return Diagnostic(
            "Docker daemon",
            FAILED,
            f"docker info failed ({exc})",
            "Start Docker Desktop or the Docker daemon.",
        )
    if result.returncode == 0:
        return Diagnostic("Docker daemon", OK, "running")
    return Diagnostic(
        "Docker daemon",
        FAILED,
        "the Docker daemon is not running",
        "Start Docker Desktop or the Docker daemon.",
    )


def _check_node(runner: Runner) -> Diagnostic:
    if not shutil.which("node"):
        return Diagnostic("Node.js", FAILED, "not found", "Install Node.js 20 or newer.")
    try:
        result = runner(["node", "--version"])
        version = result.stdout.strip().lstrip("v")
        major = int(version.split(".", 1)[0])
    except (OSError, subprocess.SubprocessError, ValueError, AttributeError, IndexError):
        return Diagnostic(
            "Node.js",
            WARNING,
            "installed, but its version could not be determined",
            "Run node --version and verify Node.js 20 or newer.",
        )
    if major < 20:
        return Diagnostic(
            "Node.js", FAILED, f"{version} is too old", "Install Node.js 20 or newer."
        )
    return Diagnostic("Node.js", OK, version)


def _permission_paths(environ: Mapping[str, str]) -> Iterable[Path]:
    defaults = {
        "RECONIX_DATA_DIR": "~/.reconix/assessments",
        "RECONIX_EVIDENCE_DIR": "data/evidence",
    }
    for key, default in defaults.items():
        yield Path(environ.get(key, default)).expanduser()


def _check_permissions(environ: Mapping[str, str]) -> Diagnostic:
    paths = list(_permission_paths(environ))
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        return Diagnostic(
            "Secure directories",
            WARNING,
            f"not created: {', '.join(missing)}",
            "Start the Core API or create these directories with mode 0700.",
        )
    unsafe = [str(path) for path in paths if stat.S_IMODE(path.stat().st_mode) != stat.S_IRWXU]
    if unsafe:
        return Diagnostic(
            "Secure directories",
            FAILED,
            f"not 0700: {', '.join(unsafe)}",
            "Restrict them with chmod 700 <directory>.",
        )
    return Diagnostic("Secure directories", OK, "data and evidence directories are mode 0700")


def run_diagnostics(
    root: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
    requester: Requester = _request,
    runner: Runner = _run,
    include_local_services: bool = True,
) -> DiagnosticReport:
    """Run installation checks and, for the CLI, local-service checks."""
    env: Mapping[str, str] = environ or os.environ
    config_root = _find_root(root)
    core_url = env.get("RECONIX_CORE_API_URL", env.get("RECONIX_CORE_API", "http://127.0.0.1:8000"))
    core_check = (
        _check_http(
            "Core API",
            f"{core_url.rstrip('/')}/health",
            "Start the Core API with ./deploy/dev.sh.",
            requester,
        )
        if include_local_services
        else _check_core_api_for_tui()
    )
    results = [
        _check_python(),
        _check_command(
            "uv", "uv", "Install uv: https://docs.astral.sh/uv/getting-started/installation/."
        ),
        _check_env(config_root, env),
        core_check,
        _check_node(runner),
        _check_command("npm", "npm", "Install npm with Node.js."),
        _check_permissions(env),
    ]
    if include_local_services:
        qdrant_url = env.get("RECONIX_QDRANT_URL", "http://127.0.0.1:6333").rstrip("/")
        kali_url = env.get("RECONIX_KALI_MCP_URL", "http://127.0.0.1:8096/mcp")
        results[4:4] = [
            _check_database(config_root, env, runner),
            _check_http(
                "Qdrant",
                f"{qdrant_url}/healthz",
                "Start Qdrant and verify RECONIX_QDRANT_URL.",
                requester,
            ),
            _check_docker(runner),
            _check_mcp("Kali MCP", kali_url, requester),
        ]
    return DiagnosticReport(tuple(results))


def doctor_main(console: Optional[Console] = None) -> int:
    """Run the CLI doctor and return a process exit status."""
    report = run_diagnostics()
    report.render(console or Console())
    return 0 if report.ok else 1


def report_lines(report: DiagnosticReport) -> List[Text]:
    """Build plain Rich lines for the TUI's read-only doctor dialog."""
    lines: List[Text] = []
    for result in report.results:
        symbol = {"OK": "✓", "WARNING": "⚠", "FAILED": "✗"}[result.status]
        lines.append(Text(f"{symbol} {result.name}: {result.detail}"))
        if result.remediation:
            lines.append(Text(f"  Fix: {result.remediation}"))
    return lines
