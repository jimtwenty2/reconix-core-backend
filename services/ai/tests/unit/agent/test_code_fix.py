"""The fix agent: line edits, the edit tool, the task text, one agent run and the outcomes.

Ported from the VS Code harness's tests/test_fix.py, with a scripted fake model.
"""

import json

import pytest

from reconix_ai.agent import code_fix
from reconix_ai.agent.code_fix import (
    Budget,
    EditError,
    FileCopy,
    FixStopped,
    FixTarget,
    line_edits,
)
from reconix_ai.providers import ToolCall, ToolReply


def apply(orig: list[str], edits: list[dict]) -> list[str]:
    out = list(orig)
    for edit in sorted(edits, key=lambda e: -e["start_line"]):
        new = edit["replacement"].split("\n") if edit["replacement"] else []
        out[edit["start_line"] - 1 : edit["end_line"]] = new
    return out


def copy_of(text: str, path: str = "a.py", masked: dict[int, str] | None = None) -> FileCopy:
    real = code_fix.split_lines(text)
    view = [(masked or {}).get(number, line) for number, line in enumerate(real, start=1)]
    return FileCopy(path, real, view, "0" * 64)


def target(finding_id: str = "f1", path: str = "a.py", line: int = 1, **extra) -> FixTarget:
    return FixTarget(
        finding_id=finding_id,
        path=path,
        title="SQL injection",
        severity="HIGH",
        tools=extra.pop("tools", ["SEMGREP"]),
        start_line=line,
        end_line=line,
        rule_id="python.sqli",
        **extra,
    )


def scripted(*steps: tuple[str, dict]):
    """A fake model answering each step with one tool call; records what it was sent."""
    seen: list[list[dict]] = []

    async def model(messages, tools, on_text, on_thinking):
        seen.append([dict(message) for message in messages])
        name, args = steps[len(seen) - 1]
        await on_thinking("Looking at the query. ")
        await on_text("I will fix it.")
        call = ToolCall(f"c{len(seen)}", name, json.dumps(args))
        return ToolReply("", [call], prompt_tokens=100, completion_tokens=20, masked_count=0)

    return model, seen


def no_recheck(still: set[str] | None = None, unchecked: set[str] | None = None):
    calls: list[tuple[list[str], list[str]]] = []

    async def recheck(changed, group, final):
        calls.append((sorted(changed), [t.finding_id for t in group]))
        return set(still or ()), set(unchecked or ())

    return recheck, calls


# ---------------------------------------------------------------------------
# line_edits
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "new",
    [
        ["import os", "import sys", "", "def f():", "    x = 1", "    return x"],  # middle
        ["# header", "import os", "", "def f():", "    x = 1", "    return x"],  # top
        ["import os", "", "def f():", "    x = 1", "    return x", "", "print(f())"],  # end
        ["import os", "def f():", "    return 1"],  # delete and replace
        ["import os", "import sys", "", "def f():", "    y = 2", "    return x"],  # two changes
        ["", "", "def f():", "    x = 1", "    return x"],  # a line becomes blank
        ["import os", "", "def f():", "    x = 1", ""],  # the last line becomes blank
    ],
)
def test_line_edits_rebuild_the_new_file(new):
    orig = ["import os", "", "def f():", "    x = 1", "    return x"]
    edits = line_edits(orig, new)
    assert apply(orig, edits) == new
    assert all(e["start_line"] <= e["end_line"] for e in edits)
    assert all(a["end_line"] < b["start_line"] for a, b in zip(edits, edits[1:], strict=False))


def test_line_edits_of_an_unchanged_or_empty_file():
    assert line_edits(["a"], ["a"]) == []
    assert line_edits([], ["a"]) == []  # an empty file has no line to replace


def test_split_lines_counts_like_vscode():
    assert code_fix.split_lines("a\r\nb\n") == ["a", "b"]
    assert code_fix.split_lines("a\nb") == ["a", "b"]
    assert code_fix.split_lines("") == []


# ---------------------------------------------------------------------------
# The edit tool
# ---------------------------------------------------------------------------


def test_edit_is_exact_unique_and_keeps_secrets():
    copy = copy_of(
        'KEY = "sk_live_abcdefghijklmnop"\nx = 1\nx = 1\ny = 2\n',
        masked={1: 'KEY = "[MASKED:api_key]"'},
    )
    view = copy.read()
    assert "sk_live" not in view and "[MASKED:api_key]" in view
    for old, new, error in [
        ("x = 1", "x = 2", "appears 2 times"),
        ("nope", "", "not found"),
        ("", "x", "empty"),
        ('KEY = "[MASKED:api_key]"', 'KEY = "[MASKED:api_key]"  # kept', "hidden secret"),
    ]:
        with pytest.raises(EditError, match=error):
            copy.edit(old, new)
    copy.edit("x = 1\ny = 2", "x = 1\ny = 3")
    copy.edit('KEY = "[MASKED:api_key]"', 'KEY = os.environ["KEY"]')
    assert copy.real == ['KEY = os.environ["KEY"]', "x = 1", "x = 1", "y = 3"]
    proposal = copy.proposal()
    assert proposal is not None and apply(copy.orig, proposal.edits) == copy.real
    assert all("sk_live" not in edit["replacement"] for edit in proposal.edits)


def test_a_hidden_line_is_never_copied_into_the_result():
    # Inserting right after a hidden line takes it as the edit's neighbour line: refused.
    copy = copy_of('TOKEN = "abc123"\n', masked={1: "[MASKED]"})
    copy.real.append("print('hi')")  # as an edit below it would leave it
    copy.masked.append("print('hi')")
    with pytest.raises(EditError, match="secret"):
        copy.proposal()


def test_read_and_search_show_the_masked_view():
    copy = copy_of("a = 1\npassword = 'hunter22'\nb = 2\n", masked={2: "[MASKED]"})
    assert "hunter22" not in copy.read(1, 3) and "(lines 1-3 of 3)" in copy.read(1, 3)
    assert copy.search("password") == "No matches."
    assert copy.search("b =") == "3: b = 2"
    assert copy.read(9) == "a.py has only 3 lines."


def test_small_files_go_into_the_task_whole():
    small = copy_of("".join(f"x{i} = {i}\n" for i in range(1, 51)), "small.py")
    text = code_fix.task_text(small, [target(path="small.py", line=25)], "abcd")
    assert "The whole file" in text and "x1 = 1" in text and "x50 = 50" in text
    assert text.count("<data abcd>") == 1 and text.endswith("</data abcd>")
    lines = code_fix.WHOLE_FILE_LINES + 50
    big = copy_of("".join(f"y{i} = {i}\n" for i in range(1, lines)), "big.py")
    text = code_fix.task_text(big, [target(path="big.py", line=200)], "abcd")
    assert "The whole file" not in text and "y200 = 200" in text and "y1 = 1\n" not in text


# ---------------------------------------------------------------------------
# One request
# ---------------------------------------------------------------------------


async def test_an_agent_fixes_and_checks_its_file():
    copies = {"db.py": copy_of("q = 'a' + x\nrun(q)\n", "db.py")}
    model, seen = scripted(
        ("read_file", {}),
        ("edit_file", {"old_text": "q = 'a' + x", "new_text": "q = ('a', x)"}),
        ("check_fixes", {}),
        ("finish", {"summary": "Used a parameter.", "fixed": ["f1"]}),
    )
    recheck, calls = no_recheck()
    events: list[tuple] = []

    async def say(file, kind, text):
        events.append((file, kind, text))

    output = await code_fix.fix_files(
        model, copies, [target(path="db.py")], recheck, say, Budget(10_000)
    )
    assert [f.path for f in output.files] == ["db.py"]
    assert output.files[0].edits == [
        {"start_line": 1, "end_line": 1, "replacement": "q = ('a', x)"}
    ]
    assert [(r.finding_id, r.status) for r in output.results] == [("f1", "FIXED")]
    assert output.summary == "- `db.py`: Used a parameter."
    assert output.tokens == 4 * 120
    assert calls == [(["db.py"], ["f1"]), (["db.py"], ["f1"])]  # the agent's check, the last one
    assert "no longer reported" in seen[3][-1]["content"]  # what check_fixes told the agent
    assert ("db.py", "START", "1 finding") in events
    assert ("db.py", "TOOL", "Edit db.py") in events
    assert ("db.py", "RESULT", "+1 −1 lines") in events
    assert (None, "STATUS", "Checking all changes with the scanners") in events
    assert ("db.py", "DONE", "Finished 1 of 1 files") in events
    assert any(kind == "THINKING" for _, kind, _ in events)
    assert all(text for _, kind, text in events if kind in ("TEXT", "THINKING"))
    # Code and tool results reach the model only inside the data fence.
    task = seen[0][1]["content"]
    fence = task.split("<data ", 1)[1].split(">", 1)[0]
    assert f"</data {fence}>" in seen[1][-1]["content"]


async def test_outcomes_for_each_kind_of_finding():
    copies = {"a.py": copy_of("x = eval(y)\n"), "b.py": copy_of("z = 1\n", "b.py")}
    model, _ = scripted(
        ("edit_file", {"old_text": "x = eval(y)", "new_text": "x = int(y)"}),
        ("finish", {"summary": "Done."}),
        (
            "finish",
            {"summary": "False alarm.", "not_fixed": [{"id": "b1", "reason": "Not a bug."}]},
        ),
    )
    targets = [
        target("a1"),  # SEMGREP, still reported
        target("a2", tools=["SONAR_SCAN"]),  # changed, cannot be checked
        target("b1", path="b.py"),  # its file is not changed
        target("leak", tools=["GITLEAKS"], not_fixable="Rotate it."),
    ]
    recheck, _ = no_recheck(still={"a1"}, unchecked={"a2"})

    async def say(file, kind, text):
        pass

    output = await code_fix.fix_files(
        model, copies, targets, recheck, say, Budget(10_000), max_parallel=1
    )
    got = {r.finding_id: (r.status, r.note) for r in output.results}
    assert got["a1"][0] == "STILL_REPORTED"
    assert got["a2"][0] == "NOT_VERIFIED"
    assert got["b1"] == ("NOT_FIXED", "Not a bug.")
    assert got["leak"] == ("NOT_FIXED", "Rotate it.")
    assert [r.finding_id for r in output.results] == ["a1", "a2", "b1", "leak"]  # request order


async def test_a_model_without_tools_changes_nothing():
    async def model(messages, tools, on_text, on_thinking):
        return ToolReply("Here is how I would fix it.", [], 10, 10, 0)

    recheck, calls = no_recheck()

    async def say(file, kind, text):
        pass

    output = await code_fix.fix_files(
        model, {"a.py": copy_of("x = 1\n")}, [target()], recheck, say, Budget(10_000)
    )
    assert output.files == [] and calls == []
    assert output.results[0].status == "NOT_FIXED"
    assert "tool calls" in output.summary


async def test_the_token_budget_stops_the_agents():
    model, seen = scripted(*[("read_file", {})] * 30)
    recheck, _ = no_recheck()

    async def say(file, kind, text):
        pass

    output = await code_fix.fix_files(
        model, {"a.py": copy_of("x = 1\n")}, [target()], recheck, say, Budget(250)
    )
    assert len(seen) == 3  # 120 tokens a step: stops once 250 are spent
    assert "token budget" in output.summary


async def test_stopping_ends_every_agent():
    async def model(messages, tools, on_text, on_thinking):
        raise FixStopped

    recheck, _ = no_recheck()

    async def say(file, kind, text):
        pass

    copies = {"a.py": copy_of("x = 1\n"), "b.py": copy_of("y = 1\n", "b.py")}
    with pytest.raises(FixStopped):
        await code_fix.fix_files(
            model, copies, [target(), target("b", path="b.py")], recheck, say, Budget(10_000)
        )


async def test_bad_tool_calls_go_back_to_the_model():
    model, seen = scripted(
        ("edit_file", {"old_text": "missing", "new_text": "x"}),
        ("nope", {}),
        ("finish", {"summary": "Gave up."}),
    )
    recheck, _ = no_recheck()

    async def say(file, kind, text):
        pass

    await code_fix.fix_files(
        model, {"a.py": copy_of("x = 1\n")}, [target()], recheck, say, Budget(10_000)
    )
    assert "Error: old_text was not found" in seen[1][-1]["content"]
    assert seen[2][-1]["content"] == "Error: unknown tool nope"


def test_an_edit_may_not_silence_the_scanner():
    copy = copy_of("os.system(cmd)\n")
    for comment in ("  # nosemgrep", "  # noqa: S605", "  // eslint-disable-line", "  # NOSEC"):
        with pytest.raises(EditError, match="silences the scanner"):
            copy.edit("os.system(cmd)", "os.system(cmd)" + comment)
    kept = copy_of("x = 1  # noqa: E501\n")
    kept.edit("x = 1", "x = 2")  # one already there is not added by the edit
    assert kept.real == ["x = 2  # noqa: E501"]


async def test_too_many_tool_calls_in_one_step_are_refused():
    seen: list[list[dict]] = []

    async def model(messages, tools, on_text, on_thinking):
        seen.append([dict(m) for m in messages])
        if len(seen) == 1:
            calls = [ToolCall(f"c{n}", "read_file", "{}") for n in range(12)]
        else:
            calls = [ToolCall("end", "finish", '{"summary": "ok"}')]
        return ToolReply("", calls, 1, 1, 0)

    recheck, _ = no_recheck()
    events: list[tuple] = []

    async def say(file, kind, text):
        events.append((file, kind, text))

    await code_fix.fix_files(
        model, {"a.py": copy_of("x = 1\n")}, [target()], recheck, say, Budget(10_000)
    )
    replies = [m for m in seen[1] if m["role"] == "tool"]
    assert len(replies) == 12  # every call gets an answer, as the API requires
    assert sum("at most 8 tool calls" in m["content"] for m in replies) == 4
    assert sum(kind == "TOOL" and text.startswith("Read") for _, kind, text in events) == 8


async def test_a_huge_number_is_a_bad_argument_not_a_failure():
    model, seen = scripted(("read_file", {"start_line": 1e999}), ("finish", {"summary": "ok"}))
    recheck, _ = no_recheck()

    async def say(file, kind, text):
        pass

    output = await code_fix.fix_files(
        model, {"a.py": copy_of("x = 1\n")}, [target()], recheck, say, Budget(10_000)
    )
    assert "Error: bad arguments (OverflowError)" in seen[1][-1]["content"]
    assert output.summary == "- `a.py`: ok"
