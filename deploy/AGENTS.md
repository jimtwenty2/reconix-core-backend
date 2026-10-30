# AGENTS.md — Deploy

Owner: Vanneth (`lab/`: Youlong; `seed.sql`: Sreyleak) · Last reviewed: 28 Oct 2026

Read the root [`AGENTS.md`](../AGENTS.md) first. These rules add to it; if they disagree, the root
file wins.

Scope: how Reconix starts on one computer: Docker Compose, the test lab, sample data and the
installer.

**Plan:** [`docs/reconix-plan-v2.md`](../docs/reconix-plan-v2.md). The API joins Compose and
`install.sh` is written in week 2 (by **Mon 2 Nov**). Fresh-install tests run on Wed 4 Nov and
Mon 23 Nov; deployment is done on **Fri 27 Nov**.

## Files

| File | Holds |
|---|---|
| `docker-compose.yml` | The local stack: `postgres` (16), `qdrant`, `ollama`, `kali-mcp`, plus the one-off `nuclei-templates` (profile `setup`) that fills the read-only templates volume `kali-mcp` uses |
| `docker-compose.dev.yml` | Dev only: while the API runs on the host, a small relay (`kali-mcp-relay`) publishes the Kali MCP port on `127.0.0.1` (`RECONIX_MCP_PORT`). Kali itself keeps no published port: Docker drops ports on a container with only internal networks. Drop the file once the API runs in Compose |
| `lab/` | Test targets: OWASP Juice Shop and a small repo with known bugs and a fake secret (empty, to build) |
| `seed.sql` | Sample data matching ERD V3; `apps/sample-data/` is built from it (placeholder) |
| `install.sh` | Installs Reconix-Core (backend, terminal app, local web) and pulls the Kali image (placeholder) |

## Networks

| Network | Who is on it | Internet |
|---|---|---|
| `backend` | `postgres`, `qdrant`, `ollama` (and the API, once it runs in Compose) | Yes |
| `tools` | API ↔ `kali-mcp` (in dev: `kali-mcp-relay` ↔ `kali-mcp`) | **No** (`internal: true`) |
| `reconix-lab` | `kali-mcp` ↔ lab targets | **No** (`internal: true`) |
| `mcp-host` (dev only) | `kali-mcp-relay` only, so Docker can publish its port | Yes |
| `downloads` | the one-off `nuclei-templates` only | Yes |

## Rules

- **Loopback only.** Every published port binds to `127.0.0.1`, never `0.0.0.0` or a bare port.
- **The Kali container stays locked down.** No published port in `docker-compose.yml`, only the
  `tools` and `reconix-lab` networks, both internal. Keep `cap_drop: [ALL]`, only `NET_RAW`,
  `NET_ADMIN` and `NET_BIND_SERVICE` (nmap needs all three), and `no-new-privileges`. Never add
  `privileged`, host networking or a Docker socket mount.
- **One exception: the nuclei templates download.** Only the one-off `nuclei-templates`
  service (profile `setup`) runs the Kali image with internet, on its own `downloads` network.
  It never joins `tools` or `reconix-lab`, its entrypoint is fixed to the template update, it
  keeps `cap_drop: [ALL]` and `no-new-privileges`, and `kali-mcp` mounts the result read-only.
- **Tools run only against the lab.** Nothing in this folder may point a tool at a target outside
  `reconix-lab`.
- **Pinned images.** Use exact tags (for example `qdrant/qdrant:v1.13.2`), never `latest`. The Kali
  image is `RECONIX_KALI_IMAGE`: the `:dev` test image until the first release, then a numbered tag.
- **Secrets come from `.env`.** Required values use `${VAR:?message}` so Compose fails loudly when
  one is missing. Never write a real secret, default password or key into a file here. New
  variables go into `.env.example` in the same PR.
- **Names match `RECONIX_*` settings** in `services/api/src/reconix_api/core/config.py`.
- **`seed.sql` uses ERD V3 names and UPPERCASE enum values**, with obvious fake data. After changing
  it, rebuild `apps/sample-data/` so the TUI, the web and the database show the same examples.
- **`install.sh`:** `set -euo pipefail`, quote every variable, no `curl | sh` of unpinned scripts,
  and never ask for or store a provider API key.
- **The API image needs Pango** (`libpango-1.0-0`, `libpangoft2-1.0-0` on Debian): the AI
  Service draws the PDF report with WeasyPrint. Install it in the image when the API moves into
  Compose, and check for it in `install.sh`.
- A change here that affects how other parts start (ports, variable names, networks) must be called
  out in the PR so their owners can check it.

## Plan status (28 Oct 2026)

Keep this table true; update the row in the PR that changes it.

| Plan item | Week | Owner | Status |
|---|---|---|---|
| Compose: Postgres 16, Qdrant, Ollama, Kali container on a private network | 1 | Vanneth | Done |
| Lab: `reconix-lab` network with Juice Shop and a test repo with known bugs and a fake secret | 1 | Youlong | Network exists; targets to add in `lab/` |
| `seed.sql` matching ERD V3, sample files rebuilt from it | 1 | Sreyleak | To do (placeholder) |
| API (and every backend service) in Compose; one command starts everything | 2 | Vanneth | To do: API runs on the host with `docker-compose.dev.yml` |
| `install.sh` and uv install steps (backend, TUI, web, Kali image) | 2 | Vanneth | To do (placeholder) |
| Clean demo data on the lab for Wed 4 Nov | 3 | Youlong | To do |
| Fresh install with uv and with `install.sh` (Wed 4 Nov, Mon 23 Nov) | 3, 5 | Vanneth | To do (`cut-release` skill) |

## Commands

Run from the repo root.

```bash
# dev: the API runs on the host
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml --env-file .env up -d
# once after the first up, and to update: kali-mcp has no internet to fetch nuclei templates
docker compose -f deploy/docker-compose.yml --env-file .env run --rm nuclei-templates

docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs -f kali-mcp
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml down  # -v wipes the data volumes and the nuclei templates

# check a change before the PR
docker compose -f deploy/docker-compose.yml --env-file .env config --quiet
bash -n deploy/install.sh
```

## Done when

- `docker compose ... config --quiet` passes and the stack starts with `up -d`; every service is
  healthy in `ps`.
- No port is published outside `127.0.0.1`, and the Kali container still has no published port and
  no internet.
- The full flow still runs (`run-full-flow-test` skill) if a service, network or variable changed.
- `.env.example` and the "Plan status" table above are updated when needed.
