"""check_command_line(): a typed `/name [arg]` against the registry, without running it."""

import pytest

from reconix.commands import COMMANDS, check_command_line
from reconix.commands.registry import Command, suggest
from reconix.models import Choice


def _noop(app, arg) -> None:
    pass


@pytest.mark.parametrize(
    "text, name, arg",
    [
        ("/plan", "plan", None),
        ("/findings", "findings", None),
        ("/export pdf", "export", "pdf"),
        ("/new https://app.example.com", "new", "https://app.example.com"),
        ("/assess http://target.example", "assess", "http://target.example"),
        ("/list", "assessments", None),  # an alias
    ],
)
def test_valid_lines_find_their_command(text, name, arg):
    check = check_command_line(COMMANDS, text)
    assert check.ok and check.error == ""
    assert (check.command.name, check.arg) == (name, arg)


@pytest.mark.parametrize(
    "text, name",
    [
        ("/PLAN", "plan"),
        ("  /Plan  ", "plan"),
        ("/FiNdInGs", "findings"),
        ("\t/report ", "report"),
    ],
)
def test_names_ignore_case_and_surrounding_spaces(text, name):
    check = check_command_line(COMMANDS, text)
    assert check.ok and check.command.name == name


@pytest.mark.parametrize(
    "text, near",
    [
        ("/plna", "plan"),
        ("/fidnings", "findings"),
        ("/reprot", "report"),
        ("/hlep", "help"),
    ],
)
def test_an_unknown_command_suggests_the_closest(text, near):
    check = check_command_line(COMMANDS, text)
    assert not check.ok and check.command is None
    assert check.error == (
        f'Unknown command "{text}". Did you mean /{near}? Type / to see all commands.'
    )


def test_an_unknown_command_with_nothing_close_has_no_suggestion():
    check = check_command_line(COMMANDS, "/xyzzy")
    assert check.error == 'Unknown command "/xyzzy". Type / to see all commands.'


def test_the_scan_example_from_the_spec():
    commands = (Command("scan", "Scan", _noop),)
    check = check_command_line(commands, "/scna")
    assert check.error == (
        'Unknown command "/scna". Did you mean /scan? Type / to see all commands.'
    )


def test_an_alias_suggests_its_command():
    assert suggest(COMMANDS, "exitt").name == "quit"


def test_a_bare_slash_asks_for_a_name():
    check = check_command_line(COMMANDS, "/")
    assert not check.ok and "Type a command after /" in check.error


def test_an_argument_to_a_command_that_takes_none_shows_its_usage():
    check = check_command_line(COMMANDS, "/plan now")
    assert check.error == "/plan takes no argument. Usage: /plan"


def test_a_missing_required_argument_shows_the_usage():
    check = check_command_line(COMMANDS, "/assess")
    assert check.error == "/assess needs a target. Usage: /assess <target>"


def test_a_choice_that_isnt_offered_shows_the_usage_and_choices():
    commands = (
        Command(
            "export",
            "Export",
            _noop,
            arg="OPTIONAL",
            arg_name="format",
            choices=lambda app: [Choice("pdf", "PDF"), Choice("json", "JSON")],
        ),
    )
    check = check_command_line(commands, "/export xls", app=object())
    assert check.error == (
        '"xls" isn\'t a format here. Usage: /export [format] — one of: pdf, json'
    )
    assert check_command_line(commands, "/export PDF", app=object()).ok


def test_choices_are_only_checked_when_an_app_is_given():
    assert check_command_line(COMMANDS, "/export xls").ok


@pytest.mark.parametrize(
    "name, usage",
    [
        ("plan", "/plan"),
        ("new", "/new [target]"),
        ("export", "/export [format]"),
        ("assess", "/assess <target>"),
    ],
)
def test_usage_lines(name, usage):
    assert next(c for c in COMMANDS if c.name == name).usage == usage


def test_every_argument_spec_is_known_and_named():
    for command in COMMANDS:
        assert command.arg in ("NONE", "OPTIONAL", "REQUIRED"), command.name
        assert (command.arg == "NONE") == (command.arg_name == ""), command.name
        if command.choices is not None:
            assert command.arg != "NONE", command.name
