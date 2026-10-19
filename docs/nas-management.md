# Restricted NAS application management (pilot)

This page describes fixed, administrator-enrolled projects. For optional creation
and changes inside an administrator-defined envelope, see
[policy-constrained provisioning](project-provisioning.md). That separate endpoint
does not relax the fixed-action endpoint or accept arbitrary Compose/YAML.

The Mac agent gets a private HTTPS application-action API, **not** DSM, SSH,
Docker credentials, arbitrary Compose, shell, `exec`, prune, or storage APIs.
This is an implementation foundation, not a claim of tested DSM compatibility.
No existing NAS containers, shares, backups or VPS installations are changed.

For DSM-specific network and directory wiring, use the
[minimal Synology profile](synology.md), reusing DSM's existing HTTPS proxy.

## Trust boundary

```
Mac client -- private HTTPS / HMAC --> management API (unprivileged)
                                        | fixed Unix stream socket
                                  Runner action broker (privileged)
                                        | administrator-fixed Compose project/services
                                    NAS Docker daemon

update --> fixed Verifier socket --> existing Cosign/digest verification --> Runner
```

Receiver → Verifier → Runner remains the deployment pipeline. The optional
management container is a second unprivileged entrypoint, with no Docker socket,
source policies, candidates, production data or writable administrator policy.
Keeping it separate also keeps management credentials/replay state out of GitHub
webhook handling. All roles use the same engine image and run on the NAS; no VM.
Runner has no network. Do not expose management through the public webhook route.

**Runner still has host-admin-equivalent Docker socket access.** Read-only policy,
capability drops and fixed actions constrain the caller, not a compromised Runner.
Compromise of that component can bypass these limits. A generic Docker socket
proxy allowing container creation does not remove that risk. The agent also
controls approved application images: those images can read/write the data and
reach the networks granted to that application. NAS backups must not be writable
or administrable by these application containers or the Mac account.

## Administrator-only enrollment

Start with an empty dedicated test application and test data. Do not point the
pilot at existing Immich photos, databases, media, or unrelated Compose projects.
An administrator uses DSM Container Manager's project UI to install the verified
pinned engine image. The Mac agent never receives DSM/SSH/Docker credentials.

1. Verify DSM version, CPU architecture, installed Docker daemon version, Compose
   CLI compatibility, bind-mount semantics, UID/GID/ACL behavior and Unix sockets
   on **this NAS**. Use the DSM UI to inspect state/logs; do not grant agent SSH.
   Bind mounts must resolve to the **same absolute paths** inside Runner and on
   the Docker host. A normal VPS path example is not a Synology path mapping.
2. Keep engine configuration and managed Compose definitions in dedicated
   administrator-owned directories, outside every application-writable mount.
   All parents of the API policy must be root-owned, not group/world writable,
   without symlinks. Use root-owned 0644 policy/Compose files; never let the Mac
   account, app UID, or Synology Drive edit them. Protect `.env`, `env_file`,
   Compose includes/extends, secrets and every other referenced configuration too.
3. Approve exact services, image repositories/signing identities, network access,
   and app storage once. No privileged containers, Docker/DSM sockets, host PID/
   IPC/network namespaces, arbitrary devices/capabilities, or host root mounts.
   Dedicated app shares/UIDs must exclude unrelated shares and backup locations.
   Do not mount engine directories into applications. Synology ACLs must not
   override the intended POSIX restriction. New mounts/apps require re-enrollment.
4. Use existing `sources`/`targets`/`routes` policies. In the target set:

   ```json
   {
     "snapshot_paths": [],
     "rollback": false,
     "require_readiness": true,
     "management": {
       "socket": "/run/compose-cd-management/example-app.sock",
       "verifier_socket": "/run/compose-cd/example-app-verify.sock",
       "actions": ["status", "logs", "diagnose", "start", "stop", "restart", "update"]
     }
   }
   ```

   This is a fragment, not a complete target. Services are always the complete
   fixed service set in that target, never names supplied by the caller. Enable
   Docker HEALTHCHECK or a meaningful administrator-fixed `healthchecks` argv for
   every service. A running container or TCP listener alone is insufficient.
   Keep `observe: true` until the isolated deployment/recovery test passes.
5. Create `management-policy/gateway.json` from
   `examples/management-gateway.json`. Both API and Runner independently check
   project/action permissions. Prefer read-only actions initially. The private
   management secret is separate from all GitHub webhook secrets: root:secret-GID
   0440 on the NAS, client-owned 0600 on the Mac, at least 32 random bytes.
6. Pre-create `management-run` root:management-GID 0750; gateway user 10001 gets
   only that supplementary group. Pre-create persistent `management-state` owned
   by 10001:10001 mode 0700. Root alone writes socket-directory entries; sockets
   are 0660. Keep management GID distinct from signal/secret GIDs. Do not mount
   this directory or add its group to the webhook Receiver or Verifier.
7. Add `compose.management.yml` to the engine project and your **private** app
   mount overlay. Its extra API memory limit is 64 MiB (engine configured limits
   total 448 MiB, not measured usage; app and Docker overhead are additional).
   Place a NAS-local TLS reverse proxy in front of port 18792. Publish no engine
   ports. Allow only the dedicated Mac account/network via firewall/VLAN rules;
   do not expose Docker TCP. TLS verification is mandatory for the client.
   VLAN isolation alone is not authentication. If the VPS forwards traffic,
   use a private authenticated tunnel, preserve end-to-end request authentication,
   and keep this route separate from public GitHub hooks.

The public repository contains no real NAS paths, accounts, credentials or app
inventory. Record those only in private administrator configuration.

## Operations

```
python3 scripts/manage.py status example-app \
  --endpoint https://nas-management.example.invalid/v1/manage \
  --secret-file /private/path/management.key
```

Actions: `status`, `logs`, `diagnose`, `start`, `stop`, `restart`, `update`.
There is deliberately no arbitrary diagnostic command. `diagnose` runs the same
fixed readiness checks as deployment. Start/restart affect **existing** containers
only; creating/recreating containers goes through verified deployment. Stop never
uses `down`, removes volumes or acts on dependencies. Restart uses `--no-deps`.
`update` only asks Verifier to reconcile its administrator-approved source;
`accepted` means verification requested, **not** deployment successful.

POST `/v1/manage` accepts exactly `project`, `action`, `request_id` (32 lowercase
hex chars), `timestamp` (integer epoch seconds). `X-Management-Signature` is
`sha256=` plus HMAC-SHA256 over exact UTF-8 JSON body bytes. Each request must be
within ±60 seconds. Persisted SQLite UNIQUE nonces reject replay at API and broker
boundaries, even after restart. Keep NAS/Mac clocks synchronized. Bound requests
are 2 KiB; one socket/HTTP request has no caller-selected paths/arguments.

Mutations and deployments share the same global lock. A concurrent action returns
`busy`; do not automatically retry mutations. A slow action can outlive the API's
10-second response timeout: `outcome_unknown` is not failure, and replaying a
restart is unsafe. Query `status` after it completes. It returns the last action's
request ID/result and current container/deployment states; during execution it may
return `busy`. A last action left `running` after a process crash has unknown
outcome and requires reconciliation, not automatic replay. Do not use a proxy that automatically retries management POSTs.

`logs` returns **only severity counts**, last 100 lines/5 minutes, at most 32 KiB
per service. Message contents are withheld, not regex-redacted. Unstructured logs
count as `other`. This intentionally sacrifices free-form troubleshooting to
avoid exposing arbitrary tokens, paths, user data or attacker-authored content.
The agent must request a new administrator-approved structured diagnostic when
these summaries are insufficient; it cannot escalate to shell or raw logs.

Audit records contain only project, action, request ID, timestamp and status.
The engine retains the current and one previous audit file, rotating at 2 MiB.
Administrators can archive `state/management-audit*.jsonl` externally; never return raw Docker
stderr, healthcheck output, env, mounts or stack traces through this API.
Status/health metadata and severity counts remain observable application data;
protect this endpoint even though raw messages are withheld.

## Backups, failure, and recovery

NAS backup/snapshot management is **outside this engine**. Management targets
reject nonempty `snapshot_paths` and require `rollback: false`: no tar snapshots,
media traversal, rollback deletion, or implicit database/image rollback. Existing
VPS targets without management keep their configured behavior.

A partial deployment failure with rollback disabled records `recovery_required`,
never `rolled_back`. That candidate is not automatically reapplied by polling.
For management targets a persistent `state/<project>.recovery-required.json`
latch also blocks newer deployments and start/restart. This guard is written
before container recreation and cleared only after verified deployment success;
a Runner crash during deployment therefore cannot silently reapply a potentially
migrated database update. Stop, diagnostics and status
remain available. After completing external recovery and verifying state, only an
administrator can remove that latch; no agent API can acknowledge recovery.
`observe: true` can additionally pause the source during investigation.
Successful stop/restart only reports the operation, not a new deployment receipt.
A failed readiness check reports failure even if some services already restarted.

Before unattended stateful updates, the NAS owner must verify existing backups and
exercise their external recovery workflow. Database migrations may need matching
application/database recovery; changing the old image back is not data recovery.
Immich multi-image release coordination is **not implemented** here; do not enroll
Immich for unattended updates yet. AutoBangumi end-to-end NAS testing is also
pending; no production NAS validation is claimed by passing Python/CI tests.

## Acceptance on real DSM (administrator-run)

- Verify Docker/Compose compatibility and group/ACL restrictions; unrelated
  containers/shares cannot be accessed through this API.
- Inspect effective app Compose/mounts and ensure agent/app cannot edit policy.
- Bad HMAC, stale/repeated nonce, unknown project/action/service/image/mount/argv
  must fail before any Docker action. Close both API and socket access to other
  NAS users/containers.
- Exercise status/log counts/readiness/start/stop/restart and a signed update on
  disposable data; verify rejection of unsigned/wrong-source candidates.
- Force partial failure and verify truthful recovery receipt and untouched media.
- Test NAS-owned recovery, clock skew, gateway restart, client timeout, disk-full,
  container restart, resource overhead and private-network reachability.

References: [DSM projects](https://kb.synology.com/en-us/DSM/help/ContainerManager/docker_project),
[Docker daemon security](https://docs.docker.com/engine/security/),
[Immich backup/recovery](https://docs.immich.app/administration/backup-and-restore/).
