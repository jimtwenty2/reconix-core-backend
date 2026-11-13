# tools_info

## When to use

Reports the MCP tools this container exposes and the installed binary and package versions, read
from `/opt/kali-versions`. Use it to discover what capabilities the container has and to verify a
tool is present before calling it. It is a read-only inventory call, not a scan, so reach for it
first when you are unsure which tools exist or which versions are installed.

## Key options

tools_info takes no arguments: its input schema lists no properties and nothing is required. Call
it on its own to get the current tool list and versions — there is no target, option or timeout to
set.

## Output

The list of MCP tools the container exposes plus the installed binary and package versions read
from `/opt/kali-versions`. Reconix has no reader for tools_info, so no findings are parsed; the
masked output is kept on the tool run. Use it to confirm a tool is present and to check its
version before calling it.

## Risk notes

The catalog baseline is `low` and the entry is read-only, so under S4 a tools_info call runs
without waiting for a person, and anything above the scope's `max_risk` is `BLOCKED`.
`risk_ops.json` has no entry for it. It reaches no external target, reading only the container's
own tool list and version files; S3 still requires tools_info to be among the scope's allowed
tools.
