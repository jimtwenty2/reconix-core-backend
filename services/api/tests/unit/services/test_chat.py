from reconix_api.services.chat import step_line

NMAP = {"tool": "NMAP", "target": "172.20.0.5", "arguments": ["-Pn", "-p", "22"]}


def test_a_step_line_names_its_command():
    step = {"order": 1, "title": "Find open ports", "action": NMAP}

    assert step_line(step) == "1. Find open ports (NMAP 172.20.0.5 -Pn -p 22)"


def test_a_step_without_an_action_is_just_its_title():
    assert step_line({"order": 2, "title": "Read the results"}) == "2. Read the results"
