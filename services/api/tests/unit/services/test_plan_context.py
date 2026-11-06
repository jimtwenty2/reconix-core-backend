"""The next-step context helpers: the per-output header line and the run summary that
tell the agent which tool runs already happened, so it does not repeat them. The DB-backed
recent_outputs / finding_counts are covered by the integration tests."""

from reconix_api.services.plans import RUN_LINES, output_header, runs_summary, short


def test_output_header_names_tool_target_and_status():
    assert output_header("NMAP", "10.0.0.5", "COMPLETED") == "NMAP 10.0.0.5 COMPLETED"


def test_a_long_target_is_cut_in_the_header():
    header = output_header("FFUF", "http://h/" + "a" * 200, "COMPLETED")
    assert header.startswith("FFUF http://h/")
    assert len(header.split(" ", 1)[1].rsplit(" ", 1)[0]) <= 60


def test_runs_summary_lists_every_run_newest_first():
    rows = [
        ("NMAP", "10.0.0.5", "COMPLETED", 3),
        ("NUCLEI", "http://h/", "COMPLETED", 1),
    ]
    summary = runs_summary(rows)
    assert summary.index("NUCLEI") < summary.index("NMAP")  # newest first
    assert "3 findings" in summary and "1 findings" in summary


def test_runs_summary_caps_the_list_but_counts_the_rest():
    rows = [("NMAP", f"10.0.0.{i}", "COMPLETED", 0) for i in range(RUN_LINES + 5)]
    summary = runs_summary(rows)
    assert summary.count("- NMAP") == RUN_LINES
    assert "5 older runs not shown" in summary


def test_short_leaves_normal_targets_alone():
    assert short("http://juice-shop:3000/") == "http://juice-shop:3000/"
