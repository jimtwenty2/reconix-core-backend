import json
import re
from pathlib import Path

from reconix_ai.harness import mask_secrets
from reconix_api.core.masking import mask_json, mask_output
from reconix_api.findings import nmap as nmap_findings

GENERIC = "tok9f8e7d6c5b4a39281706f5e4d3c2b1a0zz"  # no known shape: only its key name gives it away


def test_escaped_quotes_stay_valid_json_and_the_secret_goes():
    raw = json.dumps({"Line": 'client_secret: "9f8e7d6c5b4a39281706f5e4d3c2b1a0"'})
    masked, count = mask_output(mask_secrets, raw)
    assert json.loads(masked)["Line"] == 'client_secret: "[MASKED:api_key]"'
    assert "9f8e7d6c" not in masked
    assert count == 1


def test_value_under_a_secret_name_is_hidden_wherever_it_repeats():
    leak = {
        "RuleID": "generic-api-key",
        "Secret": GENERIC,
        "Match": f"service = {GENERIC}",
        "Line": f'service = "{GENERIC}"',
        "File": "config/settings.py",
    }
    masked, _ = mask_output(mask_secrets, json.dumps([leak]))
    assert GENERIC not in masked
    [item] = json.loads(masked)
    assert item["Secret"] == "[MASKED:token]"
    assert item["File"] == "config/settings.py"


def test_short_secret_values_are_not_replaced_everywhere():
    masked, _ = mask_output(mask_secrets, json.dumps({"token": "abc", "path": "/abc/file"}))
    assert json.loads(masked) == {"token": "[MASKED:token]", "path": "/abc/file"}


def test_json_lines_are_masked_line_by_line():
    raw = '{"a": "password=hunter2"}\n{"b": "fine"}\n{"c": "cut'
    masked, count = mask_output(mask_secrets, raw)
    first, second, last = masked.split("\n")
    assert json.loads(first) == {"a": "password=[MASKED:password]"}
    assert json.loads(second) == {"b": "fine"}
    assert last == '{"c": "cut'
    assert count == 1


def test_text_that_is_not_json_is_masked_as_text():
    assert mask_json(mask_secrets, "<nmaprun/>") is None
    assert mask_json(mask_secrets, "") is None
    assert mask_output(mask_secrets, "password=hunter2") == ("password=[MASKED:password]", 1)


# Real nmap 7.99 output (-sV -sC) from a lab host that sends a fake cookie and password.
LAB_NMAP = (Path(__file__).parents[2] / "fixtures" / "nmap" / "lab_fake_secrets.xml").read_text()
FAKE_SECRET = re.compile(r"FAKE(?:cookie|pass)\w*")
# Real ZAP SARIF report (zap_report) from the same lab host.
LAB_ZAP = (
    Path(__file__).parents[2] / "fixtures" / "zap" / "lab_fake_secrets.sarif.json"
).read_text()


def nmap_port(body: str) -> str:
    return (
        '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="80"><state state="open"/>{body}</port>'
        "</ports></host></nmaprun>"
    )


def test_nmap_raw_replies_are_dropped_before_saving():
    masked, _ = mask_output(mask_secrets, LAB_NMAP)
    assert FAKE_SECRET.findall(masked) == []
    assert "servicefp" not in masked and "fingerprint-strings" not in masked
    [finding] = nmap_findings.read(masked)[0]  # still read as before
    assert finding.title == "Open port 80/tcp (http, lab-test)"


def test_a_cut_off_nmap_output_still_loses_its_raw_replies():
    masked, _ = mask_output(mask_secrets, LAB_NMAP[: len(LAB_NMAP) * 2 // 3])
    assert FAKE_SECRET.findall(masked) == []


def test_xml_values_are_masked_after_the_xml_is_read():
    headers = "&#xa;  Server: x&#xa;  Set-Cookie: session=FAKEcookie42; Path=/&#xa;"
    script = f'<script id="http-headers" output="{headers}"/>'
    escaped = '<script id="x" output="password=&quot;FAKEpass42&quot;"/>'
    masked, count = mask_output(mask_secrets, nmap_port(script + escaped))
    assert FAKE_SECRET.findall(masked) == []
    assert count == 2
    assert "Server: x" in masked  # the rest of the script output is kept


def test_text_that_is_not_xml_is_masked_as_text():
    masked, count = mask_output(mask_secrets, "<not closed password=FAKEpass42")
    assert FAKE_SECRET.findall(masked) == []
    assert count == 1


def test_a_cookie_header_inside_json_is_masked():
    # As ZAP's report keeps a response's headers.
    headers = {"Server": "lab-test", "Set-Cookie": "session=FAKEcookie42; Path=/"}
    masked, _ = mask_output(mask_secrets, json.dumps({"response": {"headers": headers}}))
    assert FAKE_SECRET.findall(masked) == []
    assert json.loads(masked)["response"]["headers"]["Server"] == "lab-test"


def test_the_real_zap_report_keeps_no_cookie():
    masked, _ = mask_output(mask_secrets, LAB_ZAP)
    assert FAKE_SECRET.findall(masked) == []


def test_a_named_secret_is_hidden_where_it_repeats_in_nested_values():
    secret = "RepeatedHunter2Value"
    row = {"password": secret, "results": [f"value {secret}"], "more": {"line": secret + "!"}}
    masked, _ = mask_output(mask_secrets, json.dumps(row))
    assert secret not in masked
