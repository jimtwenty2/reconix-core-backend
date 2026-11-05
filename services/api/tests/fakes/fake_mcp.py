"""Fake of call_tool: a Kali MCP server that returns canned raw output.

Like the real one, it refuses a job token it did not expect or has already seen.
With `secret` set it checks the signature and expiry instead, as the Kali side does.
An output can be a function of the job, so it can depend on the target (a code scan's
copy folder holds only some files). tools_info answers with `versions`, the lines the
real Kali image gives for the code scan tools.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime

from reconix_api.core.interfaces import ToolJob, ToolName, ToolResult, ToolRunStatus
from reconix_api.core.job_token import InvalidJobToken, verify_job_token

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV">
  <host><status state="up"/><address addr="{target}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/></port>
      <port protocol="tcp" portid="3000"><state state="open"/>
        <service name="http" product="Node.js Express"/></port>
    </ports>
  </host>
</nmaprun>
"""


# What the real tools_info gave for the code scan tools (Step 0 probe), cut to their lines.
KALI_VERSIONS = {
    "apt": "gitleaks\t8.26.0-1+b1\ntrivy\t0.66.0-0kali1\nsyft\t1.51.0+ds-0kali1\nzsh\t5.9-8\n",
    "scanners": "semgrep==1.183.0\n",
    "grype": "Application:         grype\nVersion:             0.120.1\n",
    "osv-scanner": "osv-scanner version: 2.7.0\nosv-scalibr version: 0.5.3\n",
    "sonarqube": "sonarqube 24.12.0.100206\nsonar-scanner 8.1.0.6389\nopenjdk 17\n",
}


class FakeMcp:
    def __init__(self) -> None:
        self.issued_tokens: set[str] = set()
        self.used_tokens: set[str] = set()
        self.jobs: list[ToolJob] = []
        self.down = False  # set True to simulate the container being unreachable
        self.secret: str | None = None
        # set by a test: the raw output per tool, or a function of the job giving it
        self.outputs: dict[str, str | Callable[[ToolJob], str]] = {}
        self.versions = dict(KALI_VERSIONS)  # tools_info's versions; change one to upgrade
        self.stderr = ""  # set by a test: what the tool writes to stderr

    def expect_token(self, token: str) -> None:
        """Tests call this where the real backend would sign a token."""
        self.issued_tokens.add(token)

    async def call_tool(self, job: ToolJob) -> ToolResult:
        if self.down:
            raise ConnectionError("KALI_UNREACHABLE")
        if not self._token_is_valid(job):
            raise PermissionError("INVALID_JOB_TOKEN")
        self.used_tokens.add(job.job_token)
        self.jobs.append(job)

        if job.tool in self.outputs:
            canned = self.outputs[job.tool]
            output = canned if isinstance(canned, str) else canned(job)
        elif job.tool == "tools_info":
            output = json.dumps({"tools": [], "tool_count": 0, "versions": self.versions})
        elif job.tool == ToolName.NMAP:
            output = NMAP_XML.format(target=job.target)
        else:
            output = "[]"
        return ToolResult(
            # Like the real client: the output comes back in stdout.
            status=ToolRunStatus.COMPLETED,
            exit_code=0,
            stdout=output,
            stderr=self.stderr,
            duration_ms=1200,
        )

    def _token_is_valid(self, job: ToolJob) -> bool:
        if job.job_token in self.used_tokens:
            return False
        if self.secret is None:
            return job.job_token in self.issued_tokens
        try:
            claims = verify_job_token(job.job_token, self.secret, datetime.now(UTC))
        except InvalidJobToken:
            return False
        return claims.tool_run_id == job.tool_run_id
