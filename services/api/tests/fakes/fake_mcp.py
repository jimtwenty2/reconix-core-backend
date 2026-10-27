"""Fake of call_tool: a Kali MCP server that returns canned raw output.

Like the real one, it refuses a job token it did not expect or has already seen.
"""

from reconix_api.core.interfaces import ToolJob, ToolName, ToolResult, ToolRunStatus

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

    def expect_token(self, token: str) -> None:
        """Tests call this where the real backend would sign a token."""
        self.issued_tokens.add(token)

    async def call_tool(self, job: ToolJob) -> ToolResult:
        if self.down:
            raise ConnectionError("KALI_UNREACHABLE")
        if job.job_token not in self.issued_tokens or job.job_token in self.used_tokens:
            raise PermissionError("INVALID_JOB_TOKEN")
        self.used_tokens.add(job.job_token)
        self.jobs.append(job)

        if job.tool == ToolName.NMAP:
            output = NMAP_XML.format(target=job.target)
        else:
            output = "[]"
        return ToolResult(
            status=ToolRunStatus.COMPLETED, exit_code=0, output_file=output, duration_ms=1200
        )
