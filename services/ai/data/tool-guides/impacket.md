# impacket

## When to use

Runs one Impacket script for Windows and Active Directory work; the catalog names secretsdump,
psexec, wmiexec, GetNPUsers, GetUserSPNs and samrdump. Use it on a host nmap has already found and
enum4linux has already enumerated without credentials. The modules that authenticate need
credentials you already hold. mimikatz is not the alternative here: on this Linux container it only
lists packaged Windows binaries.

## Key options

- `module` — required. The Impacket module to run, for example `secretsdump`, `psexec`,
  `GetNPUsers`, `GetUserSPNs` or `samrdump`.
- `target` — required. The target spec: a `<host>` IP or hostname, or the account and host that an
  authenticated module needs. It is its own argument, separate from `module`.
- `opts` — module-specific options.
- `timeout` — per-call timeout in seconds.

## Output

Returns the script's own output, which depends on the module: dumped hashes, the output of a
command it ran, and so on. Reconix has no reader for impacket, so none of it is parsed into
findings; the masked output stays on the tool run, and that is where the module's result is read.

## Risk notes

The catalog baseline is `HIGH` and impacket is marked destructive, which the risk check pushes to
at least `HIGH` on its own. Under S4 every call therefore waits for a person, and one above the
scope's `max_risk` is blocked. `risk_ops.json` has no impacket entry: the file only lists tools
whose baseline can still jump, since an already-`HIGH` tool is gated at its baseline. impacket is
not a free-shell tool, so the command check blocks a control character or a shell metacharacter in
the module, the target or `opts`. Dumped hashes and the account a target spec carries are
credentials, and S8 covers them: the harness masks secrets before anything is saved, logged,
shown, sent to the model or stored in Qdrant.
