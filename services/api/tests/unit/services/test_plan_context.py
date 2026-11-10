"""The next-step context helpers: the per-output header line and the run summary that
tell the agent which tool runs already happened, so it does not repeat them. The DB-backed
recent_outputs / finding_counts are covered by the integration tests."""

from reconix_api.services.plans import (
    RUN_LINES,
    clean_output,
    output_header,
    runs_summary,
    short,
    short_error,
)


def test_output_header_names_tool_target_and_status():
    assert output_header("NMAP", "10.0.0.5", "COMPLETED") == "NMAP 10.0.0.5 COMPLETED"


def test_output_header_shows_a_non_zero_exit_code():
    # A non-zero exit often explains a failed or empty run; a clean 0 is not shown.
    assert output_header("NMAP", "10.0.0.5", "FAILED", 1) == "NMAP 10.0.0.5 FAILED exit=1"
    assert output_header("NMAP", "10.0.0.5", "COMPLETED", 0) == "NMAP 10.0.0.5 COMPLETED"


def test_a_long_target_is_cut_in_the_header():
    header = output_header("FFUF", "http://h/" + "a" * 200, "COMPLETED")
    assert header.startswith("FFUF http://h/")
    assert len(header.split(" ", 1)[1].rsplit(" ", 1)[0]) <= 60


def test_runs_summary_lists_every_run_newest_first():
    rows = [
        ("NMAP", "10.0.0.5", "COMPLETED", 3, ""),
        ("NUCLEI", "http://h/", "COMPLETED", 1, ""),
    ]
    summary = runs_summary(rows)
    assert summary.index("NUCLEI") < summary.index("NMAP")  # newest first
    assert "3 findings" in summary and "1 findings" in summary


def test_runs_summary_shows_the_reason_a_run_did_not_finish_cleanly():
    rows = [("NUCLEI", "http://h/", "FAILED", 0, "TIMED_OUT after 600s")]
    assert "TIMED_OUT after 600s" in runs_summary(rows)


def test_runs_summary_caps_the_list_but_counts_the_rest():
    rows = [("NMAP", f"10.0.0.{i}", "COMPLETED", 0, "") for i in range(RUN_LINES + 5)]
    summary = runs_summary(rows)
    assert summary.count("- NMAP") == RUN_LINES
    assert "5 older runs not shown" in summary


def test_short_leaves_normal_targets_alone():
    assert short("http://juice-shop:3000/") == "http://juice-shop:3000/"


def test_short_error_is_empty_for_a_clean_run_and_capped_otherwise():
    assert short_error(None) == ""
    assert short_error("  a\n  b ") == "a b"  # whitespace collapsed to one line
    capped = short_error("x" * 500)
    assert len(capped) <= 200 and capped.endswith("…")


def test_clean_output_drops_the_banner_and_heavy_json_fields():
    raw = (
        "__ _ ____  projectdiscovery.io  v3.11.1\n"  # the nuclei ASCII banner
        "[INF] Current nuclei version: v3.11.1\n"  # a progress/version line
        '{"template-id":"swagger-api","info":{"name":"Swagger","severity":"info"},'
        '"matched-at":"http://h/api-docs","request":"GET / HTTP/1.1 ...",'
        '"response":"HTTP/1.1 200 OK <a very long html body>"}\n'
        "Server: nginx\n"  # an ordinary line
    )
    out = clean_output(raw)
    assert "projectdiscovery.io" not in out and "Current nuclei version" not in out
    assert '"request"' not in out and '"response"' not in out  # heavy HTTP fields gone
    assert "swagger-api" in out and "Swagger" in out  # the match is kept
    assert "Server: nginx" in out  # ordinary lines are kept


def test_clean_output_keeps_a_finding_summary_line():
    # Not everything with symbols is a banner: arjun's "[+] Parameters found" is a finding.
    raw = "[+] Parameters found: q, security\nhttp://juice-shop:3000/ftp/incident-support.kdbx\n"
    out = clean_output(raw)
    assert "Parameters found" in out and "incident-support.kdbx" in out
