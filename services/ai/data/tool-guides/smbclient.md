# smbclient

## When to use

An SMB/CIFS client: it lists the shares of a Windows/Samba host, or runs one command against a
share, with or without credentials. Run enum4linux first — it enumerates the same host's users,
shares and groups over SMB with no credentials — and nmap before that for the open ports. Use
smbclient when the job is to act on one share rather than to enumerate the host.

## Key options

- `target` — required. The target IP or hostname.
- `share` — the share name, for example `IPC$` or `shared`. Leave it empty to list shares.
- `user` — the username. Omit it for an anonymous/null session.
- `password` — the password that goes with `user`.
- `command` — the SMB command to run, for example `ls` or `get file.txt`.
- `opts` — additional smbclient options.
- `timeout` — per-call timeout in seconds.

## Output

Returns smbclient's own output: the share list when `share` is empty, otherwise what `command`
printed. Reconix has no reader for smbclient, so no findings are parsed from it; the masked
output stays on the tool run, and that is where the share list or the directory listing is read.

## Risk notes

The catalog baseline is `MEDIUM`, but smbclient is one of the free-shell tools, with run_command,
proxychains and msfconsole. For those the command check does not block shell metacharacters
(`;`, `|`, `&`, `$`, `<`, `>` and the backtick) in the arguments, and the risk check pins the call
to at least `HIGH` whatever the baseline says. So every smbclient call waits for a person under
S4, and one above the scope's `max_risk` is blocked. `risk_ops.json` also lists `HIGH` patterns
for it — `put `, `mput`, `deltree`, `rmdir` and `rm ` — and its match rule is to lowercase the
call's argument values, join them with spaces and substring-test each pattern, the call's risk
being the higher of the baseline and the highest matching tier. Those write commands therefore
cannot raise an already-`HIGH` call further; they name what makes the call destructive in
practice. smbclient is not marked destructive in the catalog. The password you pass, and any
credential a share returns, are secrets: S8 has the harness mask them before anything is saved,
logged, shown, sent to the model or stored in Qdrant.
