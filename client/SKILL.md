---
name: nas-compose
description: Manage Docker Compose projects on the owner's Synology NAS through the Compose Deployer. Use for checking status/logs, restarting, updating images, editing compose.yaml/.env, creating projects, publishing to the tailnet, or setting up GitHub auto-deploy.
---

# NAS Compose projects

You do not have Docker or NAS access. Everything goes through `cdctl.py`, and the
owner approves with Face ID. Output is JSON.

## Read (always allowed once paired)

    python3 cdctl.py projects                       # status, images, ports, manageable, operate_until
    python3 cdctl.py logs <project> [--service s] [--tail 200]

## Operate (needs an operate grant for the project)

If `operate_until` is null, ask first and send the owner the `approval_url`:

    python3 cdctl.py request operate <project> --days 7 --wait

Then, without further approval:

    python3 cdctl.py read <project>                 # compose.yaml text and .env key names
    python3 cdctl.py restart <project> [service ...] --wait
    python3 cdctl.py start|stop|up <project> --wait
    python3 cdctl.py update <project> --wait        # pull + up; rolls back if unhealthy

## Change (one approval per change; the owner sees the diff)

Always `read` first and edit the current text; never write a compose.yaml from memory.

    python3 cdctl.py request change <project> --compose new.yaml --env-set KEY=VALUE --env-unset OLD --wait
    python3 cdctl.py request create <name> --compose compose.yaml --wait
    python3 cdctl.py request down <project> --wait
    python3 cdctl.py request serve <project> --https-port 8444 --target-port 8096 --wait
    python3 cdctl.py request trigger <project> --service web --repository owner/repo \
        --workflow .github/workflows/docker.yml --branch main --image ghcr.io/owner/repo --wait

Triggers (webhook / 30-minute polling updates; one approval each):

- pin (no `--tag`): pins one service to the signed `sha-<commit>` build of the branch head,
  editing compose.yaml/.env.
- pull (`--tag latest`): the files keep `image: <image>:<tag>`; every service running that
  image is pulled and recreated together (like Container Manager's update), and rolled back if
  unhealthy. With `--source github` (default) the tag's image must be Cosign-signed by the
  workflow on the branch. With `--source registry` (upstream images, e.g. RSSHub, RustDesk)
  there is no signature, only the tag.

      python3 cdctl.py request trigger <project> --repository owner/repo \
          --workflow .github/workflows/docker.yml --branch main --image ghcr.io/owner/repo --tag latest --wait
      python3 cdctl.py request trigger rsshub --source registry --image diygod/rsshub --tag latest --wait

## Manage (one approval per project, reusable)

    python3 cdctl.py request read --permanent --wait
    python3 cdctl.py request manage <project> --permanent --wait     # boundary derived from its files
    python3 cdctl.py request manage <project> --permanent --compose new.yaml --wait   # widen for new.yaml
    python3 cdctl.py request elevated <project> --seconds 900 --wait
    python3 cdctl.py exec --wait <project> <full-container-id> cmd args...   # ids from diagnose

Under manage, `request change|create|down` and all lifecycle actions run immediately as jobs.
`boundary_exceeded` lists what is missing (a host path, another project's network/volume, a
host feature): ask the owner with `request manage --compose`. `policy` is never approvable.

## Rules

- Tell the owner what you are asking for and why, then give them the `approval_url`.
- Job results: `success`, `rolled_back` (change failed health checks, files restored),
  `failed`, `stale` (someone changed the project in Container Manager; `read` again and
  re-propose), `unknown` (the gateway restarted; check `projects`, do not retry blindly).
- `policy` errors (privileged, docker.sock, system paths, host PID, `build:`, the deployer) cannot be approved;
  explain them to the owner instead of trying variations.
- `.env` values are never shown to you; pass secrets only via `--env-set` when the owner gives them.
- Do not use `down` to "restart" something; use `restart` or `up`.
