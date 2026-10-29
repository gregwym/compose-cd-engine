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

| Tier | What the agent can do | How it gets it |
|---|---|---|
| Read | list projects, status, images, ports, bounded logs | pairing |
| Operate | read compose.yaml, start / stop / restart / up / pull-and-update | one Passkey per project, up to 30 days |
| Change | edit compose.yaml / .env, create, down, tailnet route, webhook trigger | one Passkey per change, shown as a diff |

- Changes are written **in place** in the Container Manager project directory, with
  a backup next to the file, then `up -d` and a health check; failure restores the
  files automatically.
- The runner independently rejects privileged containers, Docker socket mounts,
  system paths, `build:` and the deployer's own directory, whatever the gateway asks.
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

Boundary JSON has mounts [{path,mode}] with canonical NAS roots and ro/rw mode,
plus external networks [name]. In-boundary edits/lifecycle/down reuse manage;
expansion requires owner approval. Elevation is finite and requires an in-container
timeout executable; it is not a hostile-code sandbox. Legacy grants are not upgraded.
See the final reusable-grants section of docs/design.md for migration and limits.
