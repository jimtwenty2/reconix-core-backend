"""Fake of call_tool: a Kali MCP server that returns canned raw output.

Like the real one, it refuses a job token it did not expect or has already seen.
With `secret` set it checks the signature and expiry instead, as the Kali side does.
"""

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


class FakeMcp:
    def __init__(self) -> None:
        self.issued_tokens: set[str] = set()
        self.used_tokens: set[str] = set()
        self.jobs: list[ToolJob] = []
        self.down = False  # set True to simulate the container being unreachable
        self.secret: str | None = None
        self.outputs: dict[str, str] = {}  # set by a test: the raw output per tool
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
            output = self.outputs[job.tool]
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
