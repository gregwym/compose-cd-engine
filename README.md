# Compose Deployer

Let an AI agent (for example OpenClaw) manage the Docker Compose projects on a
Synology NAS **without giving it access to the NAS or to Docker**. The agent calls
a small, fixed API; the owner approves each kind of action with a Passkey (Face ID).
Projects stay fully compatible with DSM Container Manager.

```
OpenClaw ─ signed HTTPS ─┐
GitHub ─ webhook ────────┤
iPhone ─ Passkey ────────┤
                         ▼
 tailscale ── gateway (one SQLite) ── unix socket ── runner ── docker.sock
                                                     network: none
```

| Grant | What the agent can do | Lifetime |
|---|---|---|
| read `*` | list projects, status, logs, structural diagnosis of everything | permanent or days |
| manage `<project>` | read files, every lifecycle action, edit compose.yaml / .env, create, down, triggers — inside the project's boundary | permanent or days |
| elevated `<project>` | `exec` argv in the project's containers | 1–3600 seconds |

Legacy one-shot `operate` / `change` / `serve` approvals still work as before.

- Changes are written **in place** in the Container Manager project directory, with
  a backup next to the file, then `up -d` and a health check; failure restores the
  files automatically.
- The runner independently rejects host takeover (privileged, Docker socket, system
  paths, host PID/IPC, kernel-level capabilities, `build:`) and anything touching the
  deployer itself, whatever the gateway asks.
- GitHub webhooks (or 30-minute polling) update one service to the Cosign-verified
  image built for the branch head.

Docs: [design](docs/design.md) (中文) · [Synology installation](docs/synology.zh-CN.md) (中文) ·
[agent skill / client](client/SKILL.md) · [security](SECURITY.md)

## Development

```sh
pip install --require-hashes --only-binary=:all: -r requirements.txt
PYTHONPATH=.:tests python3 -m unittest discover -s tests            # unit + HTTP tests
CD_DOCKER_TESTS=1 PYTHONPATH=.:tests python3 -m unittest discover -s tests   # also real Docker
```

CI runs both, validates `synology/compose.yaml`, builds the image, and on `main`
publishes `ghcr.io/kurisu-agi/compose-cd-engine:edge` (plus `sha-<commit>`) signed
with keyless Cosign.

## License

[MIT](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).

## Reusable authorization

    cdctl request read '*' --permanent --wait
    cdctl request manage app --boundary boundary.json --permanent --wait
    cdctl request change app --compose compose.yaml --wait
    cdctl request elevated app --seconds 900 --wait
    cdctl diagnose app
    cdctl exec app FULL_CONTAINER_ID echo hello

A manage request derives the project's boundary from its current files (and from
`--compose` when given): host paths outside the project directory with ro/rw, other
projects' networks/volumes, and host-level features such as `network_mode:host`,
`cap:NET_ADMIN` or `device:/dev/net/tun`. `--boundary` may add broader roots. Everything
else (tmpfs, no-new-privileges, `network_mode: service:…`, own volumes and networks,
env_file inside the boundary…) is the project's own business and never asks again.
Leaving the boundary fails with `boundary_exceeded` and the missing items; a new manage
request with `--compose` covers them. Elevation is finite and requires an in-container
timeout executable; it is not a hostile-code sandbox. See "Project boundaries" in docs/design.md.
