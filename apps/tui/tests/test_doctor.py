"""Unit tests for the Reconix installation doctor."""

import subprocess
import sys
from pathlib import Path

import pytest
from rich.console import Console

from reconix import app as app_module
from reconix.doctor import FAILED, OK, WARNING, Diagnostic, DiagnosticReport, run_diagnostics


def _env(tmp_path: Path) -> dict:
    (tmp_path / ".env.example").write_text("CORE=value\nSECOND=two\n", encoding="utf-8")
    (tmp_path / ".env").write_text("CORE=value\nSECOND=two\n", encoding="utf-8")
    return {
        "CORE": "value",
        "SECOND": "two",
        "RECONIX_DATABASE_URL": "sqlite:///" + str(tmp_path / "db.sqlite"),
    }


def _runner(command, **kwargs):
    if command[:2] == ["node", "--version"]:
        return subprocess.CompletedProcess(command, 0, stdout="v20.11.0", stderr="")
    if command[:2] == ["docker", "info"]:
        return subprocess.CompletedProcess(command, 0, stdout="Docker", stderr="")
    return subprocess.CompletedProcess(command, 0, stdout="No pending migrations", stderr="")


def test_report_is_successful_when_all_checks_pass(monkeypatch, tmp_path):
    env = _env(tmp_path)
    (tmp_path / "db.sqlite").touch()
    monkeypatch.setattr("reconix.doctor.shutil.which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr("reconix.doctor.socket.create_connection", lambda *args, **kwargs: None)
    report = run_diagnostics(
        root=tmp_path,
        environ=env,
        requester=lambda url, **kwargs: 200,
        runner=_runner,
    )
    assert not any(result.status == FAILED for result in report.results)
    assert all(result.status in (OK, WARNING) for result in report.results)


def test_missing_environment_key_has_remediation(monkeypatch, tmp_path):
    env = _env(tmp_path)
    (tmp_path / ".env").write_text("CORE=value\n", encoding="utf-8")
    report = run_diagnostics(
        root=tmp_path,
        environ=env,
        requester=lambda url, **kwargs: 200,
        runner=_runner,
    )
    result = next(item for item in report.results if item.name == ".env")
    assert result.status == FAILED
    assert "SECOND" in result.detail
    assert result.remediation


def test_service_failure_is_reported(monkeypatch, tmp_path):
    env = _env(tmp_path)
    (tmp_path / "db.sqlite").touch()
    monkeypatch.setattr("reconix.doctor.shutil.which", lambda name: "/usr/bin/" + name)
    report = run_diagnostics(
        root=tmp_path,
        environ=env,
        requester=lambda url, **kwargs: (_ for _ in ()).throw(OSError("down")),
        runner=_runner,
    )
    assert any(result.status == FAILED for result in report.results)
    assert any(
        "Start" in result.remediation for result in report.results if result.status == FAILED
    )


def test_tui_diagnostics_use_core_api_seam(monkeypatch, tmp_path):
    env = _env(tmp_path)
    monkeypatch.setattr("reconix.doctor.shutil.which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr("reconix.doctor._core_api_health", lambda: True)

    def unexpected_request(*args, **kwargs):
        raise AssertionError("TUI diagnostics must not probe services directly")

    report = run_diagnostics(
        root=tmp_path,
        environ=env,
        requester=unexpected_request,
        runner=_runner,
        include_local_services=False,
    )

    assert next(item for item in report.results if item.name == "Core API").status == OK
    assert not any(
        item.name in {"Database", "Qdrant", "Docker daemon", "Kali MCP"} for item in report.results
    )


def test_report_rendering_uses_status_badges(capsys):
    report = DiagnosticReport(
        (
            Diagnostic("Example", OK, "ready"),
            Diagnostic("Other", WARNING, "needs attention", "fix it"),
            Diagnostic("Broken", FAILED, "down", "start it"),
        )
    )
    report.render(Console())
    output = capsys.readouterr().out
    assert "[✓]" in output
    assert "[!]" in output
    assert "[✗]" in output
    assert "██████╗" in output
    assert "D O C T O R" in output
    assert "Doctor summary" in output


def test_doctor_entrypoint_does_not_start_tui(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["reconix", "doctor"])
    monkeypatch.setattr("reconix.doctor.doctor_main", lambda: 0)
    monkeypatch.setattr(app_module.ReconixApp, "run", lambda self: pytest.fail("TUI started"))
    with pytest.raises(SystemExit) as raised:
        app_module.main()
    assert raised.value.code == 0
