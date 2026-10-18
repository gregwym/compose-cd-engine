# Synology: one approved project, no extra management platform

Use this profile with DSM 7 Container Manager and DSM's existing HTTPS reverse
proxy. Older DSM/Docker packages are not assumed compatible. This is a deployment
template, **not a claim of validation on a real NAS**. Start with disposable data.

The agent only gets the management API key. It never needs DSM, SSH, Docker TCP,
shared-folder access or a Docker socket. Follow the permission and trust boundary
in [NAS management](nas-management.md); this page only supplies DSM-specific wiring.

## Minimal layout and configuration

Keep the engine directory and approved app configuration in separate,
administrator-owned folders, not Synology Drive or application-writable shares.
For example, `/volume1/compose-cd` holds engine policy/state, while
`/volume1/compose-cd-apps/example-app` holds the app's Compose/config files.
These are examples, not your NAS's actual paths. Do not relax ACLs on an existing
shared folder to make a permission error disappear: create a dedicated folder.

Copy `compose.yml`, `compose.management.yml` and
`examples/compose.synology.yml` into the private engine folder. Set privately:

```dotenv
CD_ENGINE_IMAGE=ghcr.io/kurisu-agi/compose-cd-engine@sha256:VERIFIED_64_HEX_DIGEST
CD_NAS_APP_CONFIG_DIR=/volume1/compose-cd-apps/example-app
CD_NAS_CONTROL_SUBNET=172.31.247.0/28
CD_NAS_MANAGEMENT_IP=172.31.247.2
CD_SIGNAL_GID=30001
CD_SECRET_GID=30002
CD_MANAGEMENT_GID=30003
```

The subnet/IP are examples: choose an unused private range that does not overlap
LAN, VPN or existing Docker networks; reserve the management address inside it.
Choose unused numeric groups on the actual NAS. The three groups must differ.
The bundled image supplies Python, Docker CLI, Compose and Cosign; do not mount
DSM's Docker binaries into it. Confirm client/daemon compatibility on that NAS.

An administrator prepares the directories from the enrollment instructions:

| Folder | Owner | Mode |
| --- | --- | --- |
| `routes`, `targets`, `management-policy` | root:root | 0755 |
| `sources`, `candidates` | root:signal-GID | 0750 |
| `inbox` | 10001:signal-GID | 0750 |
| `secrets` | root:secret-GID | 0750 |
| `run` | root:signal-GID | 2770 |
| `state` | root:root | 0700 |
| `management-run` | root:management-GID | 0750 |
| `management-state` | 10001:10001 | 0700 |

Use a separate random management key (at least 32 bytes), root:secret-GID 0440,
at `secrets/management.key`; the Mac copy is client-owned 0600. Do not put it in
Compose environment variables, screenshots, logs or Git. Create private
`secrets/scan-fingerprints.json` as `[]` (root:root 0600) when private scanning is
disabled. Synology ACLs and ancestor directories must preserve these boundaries.
Do not recursively change ownership on application data or existing shares.

Use the existing source/target/gateway examples with one consistent project ID.
Set the target's `compose_dir` to `CD_NAS_APP_CONFIG_DIR`, use absolute app-data
paths in its Compose file, and enable meaningful readiness checks. Set:

```json
{
  "snapshot_paths": [],
  "rollback": false,
  "require_readiness": true,
  "management": {
    "socket": "/run/compose-cd-management/example-app.sock",
    "verifier_socket": "/run/compose-cd/verify-example-app.sock",
    "actions": ["status", "logs", "diagnose"]
  }
}
```

This is a fragment. Start both action allowlists read-only and keep source/target
`observe: true`. Initially leave `routes` empty: periodic verification and the
approved `update` action work without a public GitHub webhook on the NAS.
Set `privacy_scan: false` when no private fingerprints are configured. App data,
media and NAS backup directories are **not mounted into Runner** by this profile.
New applications, storage or privileges require administrator enrollment; the
agent cannot upload Compose or enlarge its own access.

## Start and connect

From the private deployment directory, an administrator validates and starts:

```sh
docker compose -f compose.yml -f compose.management.yml -f compose.synology.yml config --quiet
docker compose -f compose.yml -f compose.management.yml -f compose.synology.yml pull
docker compose -f compose.yml -f compose.management.yml -f compose.synology.yml up -d
```

These are administrator setup commands, not an agent SSH requirement. DSM's
administrator Task Scheduler can run the one-time local setup; future operation
uses the API. Do not use the generic installer for this three-file profile.

In **Control Panel → Login Portal → Advanced → Reverse Proxy**, connect a private
HTTPS hostname with a valid certificate to `http://MANAGEMENT_CONTAINER_IP:18792`
(the fixed `CD_NAS_MANAGEMENT_IP`, not a changing container address). Apply an
access-control profile allowing only the Mac's private/VPN address. Do not forward
the management endpoint from the router or reuse a publicly accessible proxy
rule. Keep request bodies and authentication headers out of proxy logs, and do
not retry POST requests automatically. Use a dedicated source port/firewall rule
if the NAS already serves public HTTPS sites. Check access from both an allowed
client and a denied network; a private-looking DNS name is not access control.

No host ports are published, not even to localhost: Docker older than 28 has a
known same-L2 localhost-publishing limitation. Do not add a `ports` mapping or
enable external direct routing to the control network. Confirm the Mac cannot
reach raw HTTP 18792 on either NAS or container IP, including from the same
switch; only the access-controlled HTTPS rule should work. Do not assume the
DSM GUI firewall automatically covers Docker forwarding. See
[Docker port publishing](https://docs.docker.com/engine/network/port-publishing/).

Use `scripts/manage.py status example-app --endpoint
https://nas-management.example.invalid/v1/manage --secret-file /private/management.key`
from the Mac (one command). TLS certificate verification stays enabled.

After the [real-DSM acceptance checks](nas-management.md#acceptance-on-real-dsm-administrator-run),
enable `start`, `stop`, `restart` and `update` in **both** administrator allowlists
and change observation settings. Updates still require the approved signing
identity and pinned digest. Do not enable unattended Immich multi-image upgrades;
that coordination is not implemented. NAS backups remain NAS-owned.

This API withholds raw logs, environment, data and Docker errors. It does not
guarantee that an approved application image cannot leak the data/network access
granted to it. Review each application's mounts and required outbound access;
Runner remains a trusted, Docker-privileged component. No universal shell,
arbitrary image/Compose API, separate backup system or cluster is added.

References: [DSM projects](https://kb.synology.com/en-us/DSM/help/ContainerManager/docker_project?version=7),
[DSM reverse proxy](https://kb.synology.com/en-my/DSM/help/DSM/AdminCenter/system_login_portal_advanced),
[Docker daemon security](https://docs.docker.com/engine/security/).
