---
name: cut-release
description: Prepare and tag a Reconix-Core release (vX.Y.Z), including the fresh-install check with uv and with install.sh. Use when the team is ready to tag a version.
---

# Cut a release

Only cut a release after the full-flow test and the leak test pass on the merged branch.

## Checklist

1. Lint and every package's tests pass on the release branch (run them by hand; there is no CI). No open bug marked as blocking.
2. Run the `run-full-flow-test` and `run-leak-test` skills on the real stack.
3. Run the `sync-openapi` skill. `docs/openapi.json` matches the code.
4. Pin the Kali MCP image in `deploy/docker-compose.yml` to the matching **numbered** tag (not `:dev`/`latest`).
5. Bump versions in `pyproject.toml` files and `apps/web/package.json`.
6. Fresh install, twice, on a clean machine, using **only the README**:
   - with `uv`
   - with `deploy/install.sh`
   One command must start everything. Fix anything that needs a step the README does not say.
7. Ask the user before tagging and pushing. Then: `git tag -a vX.Y.Z -m "Reconix-Core vX.Y.Z"` and `git push origin vX.Y.Z`.
8. GitHub release notes: what is included, the Kali image tag, install steps, known limits.

## After the tag

- Reconix-Core only takes bug fixes until the next planned feature window.
- Other repos copy the new `docs/openapi.json`.
