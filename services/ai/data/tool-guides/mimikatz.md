# mimikatz

## When to use

Lists Kali's packaged Mimikatz Windows resources, the Win32 and x64 `.exe` and `.dll` files.
Mimikatz is Windows-only and this Linux tool does NOT run credential extraction. It reports where
those executables live so they can be transferred to a Windows target. For Windows and Active
Directory work that does run from this container, the catalog tool is impacket.

## Key options

- `opts` — reserved; Windows execution is not supported in this Linux container.
- `timeout` — per-call timeout in seconds.

Neither is required: the schema has no required properties.

## Output

Returns the locations of the packaged binaries in the Kali image, nothing read from a target.
Reconix has no reader for mimikatz, so no findings are parsed from it; the masked output stays on
the tool run, and what is kept there is a list to transfer from rather than evidence about a host.

## Risk notes

The catalog baseline is `HIGH` and mimikatz is marked destructive, which the risk check also
pushes to at least `HIGH`. Under S4 that means every call waits for a person, and one above the
scope's `max_risk` is blocked, even though this call only lists files. `risk_ops.json` has no
mimikatz entry, so no option raises a call further. mimikatz is not a free-shell tool, so the
command check blocks a control character or a shell metacharacter in `opts`. Its output is file
names rather than credentials, but S8 still applies to the run: the harness masks secrets before
anything is saved, logged, shown, sent to the model or stored in Qdrant.
