import pytest

from reconix_ai.agent.answers import (
    MAX_PLAN_STEPS,
    BadAnswer,
    json_object,
    read_plan,
    read_understanding,
)


def step(**extra: object) -> dict:
    return {"title": "Scan", "tool": "nmap", "target": "172.20.0.5", "arguments": ["-sV"], **extra}


def test_json_inside_fences_or_text_is_read() -> None:
    assert json_object('```json\n{"goal": "x"}\n```') == {"goal": "x"}
    assert json_object('Here you go: {"goal": "x"} Hope it helps.') == {"goal": "x"}


@pytest.mark.parametrize("text", ["", "no json here", "[1, 2]", "{broken"])
def test_not_a_json_object_is_a_bad_answer(text: str) -> None:
    with pytest.raises(BadAnswer):
        json_object(text)


def test_understanding_keeps_three_searches() -> None:
    goal, queries = read_understanding(
        {"goal": " Find ports ", "search": ["a", "", 5, "b", "c", "d"]}
    )

    assert goal == "Find ports"
    assert queries == ["a", "b", "c"]


def test_understanding_without_searches_searches_the_goal() -> None:
    assert read_understanding({"goal": "Find ports"}) == ("Find ports", ["Find ports"])


def test_plan_step_is_normalised() -> None:
    summary, steps = read_plan({"summary": "Go.", "steps": [step()]})

    assert summary == "Go."
    assert steps == [
        {
            "title": "Scan",
            "order": 1,
            "phase": None,
            "reason": "",
            "action": {
                "tool": "NMAP",
                "target": "172.20.0.5",
                "arguments": ["-sV"],
                "is_validation": False,
            },
        }
    ]


def test_a_known_phase_and_one_line_reason_are_kept() -> None:
    raw = step(phase=" Discovery ", reason="Find what runs first.\nrm -rf /\x1b[31m")

    _, [kept] = read_plan({"steps": [raw]})

    assert (kept["phase"], kept["reason"]) == ("discovery", "Find what runs first.")


@pytest.mark.parametrize("phase", ["exploit", 3, None, ""])
def test_an_unknown_phase_is_no_phase(phase) -> None:
    _, [kept] = read_plan({"steps": [step(phase=phase)]})

    assert kept["phase"] is None


def test_a_long_reason_is_cut() -> None:
    _, [kept] = read_plan({"steps": [step(reason="x" * 1000)]})

    assert len(kept["reason"]) == 300


def test_arguments_as_one_string_are_dropped_not_split() -> None:
    _, steps = read_plan({"steps": [step(arguments="-sV --top-ports 100"), step()]})

    assert len(steps) == 1
    assert steps[0]["action"]["arguments"] == ["-sV"]


@pytest.mark.parametrize(
    "bad",
    [
        step(target=""),
        step(arguments=["-p", 80]),
        step(title=""),
        "scan it",
        step(tool=5),
        step(tool="nikto"),  # not one of the 5 tools
    ],
)
def test_malformed_steps_are_dropped(bad: object) -> None:
    _, steps = read_plan({"steps": [bad, step()]})

    assert len(steps) == 1
    assert steps[0]["order"] == 1


def test_a_step_for_a_person_has_no_action() -> None:
    _, steps = read_plan({"steps": [{"title": "Read the results", "tool": None}]})

    assert steps[0]["action"] is None


def test_plan_is_capped() -> None:
    _, steps = read_plan({"steps": [step() for _ in range(9)]})

    assert len(steps) == MAX_PLAN_STEPS


@pytest.mark.parametrize("data", [{}, {"steps": "scan"}, {"steps": []}, {"steps": ["x"]}])
def test_plan_without_usable_steps_is_a_bad_answer(data: dict) -> None:
    with pytest.raises(BadAnswer):
        read_plan(data)
