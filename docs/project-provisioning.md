# Policy-constrained project provisioning (opt-in pilot)

This extends fixed registered-project management with **new project creation and
declaration changes**, without giving the Mac SSH, DSM credentials, a Docker
socket, or arbitrary host commands. It is an optional Runner subsystem, disabled
unless `CD_DEPLOYER_POLICY` is set. Existing targets/CD and `/v1/manage` are unchanged.

This is not general Compose upload: a closed JSON declaration is compiled into
Compose JSON. Unknown fields are rejected **before invoking Compose**. In
particular, `provider`, lifecycle hooks, build, includes/extends, caller commands,
file references, external networks, Docker volumes with driver options, devices,
privileges and host namespaces cannot be requested. Do not replace this compiler
with `compose config` on caller YAML: configuration loading itself can read host
files. See [Docker's trust model](https://docs.docker.com/compose/trust-model/).

## Trust and scope

The NAS owner installs the pinned verified engine and sets root-owned policy once.
The Mac may create/change projects **inside that envelope**, not edit the envelope.
Gateway operations and privileged Runner operations have independent allowlists.
There is still one shared HMAC identity, not multi-user RBAC. Provisioning authority
applies to the entire dedicated `cdp-` project namespace; the Mac does not gain
access to unrelated existing projects. In-place adoption of existing projects is
not implemented: do not rename or recreate them to enroll them.

Runner retains host-admin-equivalent Docker socket authority. Policy is a caller
constraint, not containment of a compromised Runner. Approved app images still
have their assigned data and network access. With `allow_egress: true`, the bridge
can reach destinations allowed by Docker/NAS routing, potentially including LAN
services: this flag is **not** an Internet-only firewall. Apply NAS/network egress
rules separately if needed. No automatic backup, restoration, database rollback,
media deletion, `down`, prune, volume removal or project deletion API is added.

## Administrator setup

1. Prepare private copies of `examples/deployer-policy.json` and
   `examples/project.json`. Those examples are inert, not a runnable application.
   Set `images` to exact fully-qualified repository names. All requests must use
   `repository@sha256:<64 lowercase hex>`. `digests: []` explicitly allows any
   digest from that approved repository; a nonempty list restricts it further.
   `allow_unsigned: true` explicitly acknowledges that this provisioning path
   does **not** perform Cosign verification. A digest pins bytes, not publisher
   authenticity. Existing signed Verifier/CD remains independent. Signed-only
   provisioning is not implemented and `allow_unsigned: false` is rejected.
2. Give each image a meaningful fixed `healthcheck` argv, using a binary present
   in that image. It is rendered as Docker HEALTHCHECK `CMD`, not shell. Do not
   use `true`, mere running state, or a TCP listener as production readiness.
   Approve exact environment variable names; values are supplied privately by
   the client. Resource limits are mandatory; memory/CPU limits are **aggregate
   reservations across managed projects**, while `max_services` is per project
   and `max_pids` is per container. CPU units are integers in this pilot.
3. Pre-create `workspace` root:root 0700 and unshared storage roots root:root 0755
   (or stricter). All their ancestors must be root-owned, not group/world writable
   and not symlinks; Synology ACLs must not grant additional write access. Workspace,
   policy, engine state/socket directories, backup locations and storage roots must
   remain separate. Never configure engine/DSM/system directories as storage.
   Paths must match **exactly** inside Runner and on the Docker host.
4. An unshared storage alias creates only `<root>/<project>/<slot>`. Its project
   parent stays root-owned; each new slot is 0750 and chowned to the configured
   nonzero UID/GID. Existing slot contents are never traversed, recursively chowned,
   deleted or restored. A shared alias binds its **entire existing root**, requires
   `slot: shared`, and creates/chowns nothing. Use shared downloads only if all
   approved projects may access them; app config should be unshared. No arbitrary
   caller subpaths or raw host paths are accepted.
5. Merge `compose.provisioning.yml` after the base and management files, with a
   private overlay mounting workspace and approved storage roots writable at the
   same absolute paths in Runner. Only Runner gets those mounts. Mount policy at
   `/etc/compose-cd/provisioning/policy.json` read-only; root owns the file and
   ancestors, mode 0644. Never mount workspace into apps/Gateway/Verifier/Receiver.
   Runner keeps `network_mode: none`; Docker daemon performs image pulls.
6. Add to private Gateway policy (keep existing project entries if needed):

   ```json
   "deployer": {
     "operations": ["plan", "apply", "task", "status", "start", "stop", "restart"]
   }
   ```

   A provisioning-only Gateway may have `"projects": {}`. Reuse the private HTTPS
   route/authentication and no-host-management-port setup in [Synology](synology.md).
   App ports bind only to the administrator's explicit private non-loopback IPv4
   address and allowed range. This exposes those **application ports** to networks
   that can reach that address; app authentication and firewall rules still apply.
   `127.0.0.1` is rejected because old Docker localhost publishing is not reliable
   same-L2 isolation. No automatic DSM proxy or firewall edits are performed.
7. Review the merged Compose config. `enabled` defaults false in the example.
   Start with disposable data; enable only after real DSM ACL/path/network and
   readiness acceptance. Root policy changes invalidate previously issued plans;
   Gateway policy changes require restarting Gateway. Workspace/storage root
   changes require administrator restart and mount review. Do not let another
   deployment system use the reserved `cdp-` namespace. A legacy registered target
   must not point at a `cdp-` project or at provisioning storage/configuration.

The additional declarations/databases are root-only and contain credentials.
SQLite transaction commits provide durable task/state updates. Project Compose
files use private atomic replacement. NAS backups remain administrator-owned;
exclude or protect these secrets according to the owner's existing backup policy.

## API and client

`POST /v1/projects` has this exact envelope (no extra fields):

```json
{
  "project": "bangumi",
  "operation": "plan",
  "request_id": "0123456789abcdef0123456789abcdef",
  "timestamp": 1792366800,
  "payload": {"services": {}}
}
```

The empty services above only illustrates the envelope; actual plans require at
least one valid service. See `examples/project.json` for the payload schema.
The HMAC header, exact-byte signing, ±60s time window and persisted replay rejection
match `/v1/manage`. The body is limited to 64 KiB. New/old schemas are disjoint;
requests cannot be replayed across routes. Keep all POST body/header logs disabled.

From the repository root (or set `PYTHONPATH` to it):

```sh
PYTHONPATH=. python3 scripts/projects.py plan bangumi --spec /private/bangumi.json \
  --endpoint https://nas.example.invalid/v1/projects --secret-file /private/management.key
PYTHONPATH=. python3 scripts/projects.py apply bangumi --id PLAN_ID \
  --endpoint https://nas.example.invalid/v1/projects --secret-file /private/management.key
PYTHONPATH=. python3 scripts/projects.py task bangumi --id TASK_ID \
  --endpoint https://nas.example.invalid/v1/projects --secret-file /private/management.key
```

Both client files must be non-symlink mode 0600 (or stricter). No credentials on
command lines. The client verifies TLS and refuses redirects; it does not retry
mutations automatically. Input/transport errors never print raw request values.

| Operation | Payload | Result |
| --- | --- | --- |
| `plan` | Complete services declaration | Immutable plan ID, revision, redacted preview, reservations |
| `apply` | `{"plan_id":"…"}` | Durable task ID |
| `task` | `{"task_id":"…"}` | Queued/running/success/failed/recovery_required/outcome_unknown |
| `status` | `{}` | Known service states, revision, recovery flag, latest task |
| `start`, `stop`, `restart` | `{}` | Durable task ID; affect existing containers only |

Plans expire after one hour and are bound to policy content and project revision.
Their previews expose image references, storage **alias/slot/target** names, ports,
resource amounts and environment **names**, never values/host paths. There is no
API to read stored declarations, Docker errors, healthcheck output or arbitrary
logs. Status is not readiness: a successful deployment/lifecycle task additionally
requires healthy checks. Raw `running` only means running.

Applying the same plan with a **fresh** signed request always returns the original
task ID, even after that task fails. Replaying a request ID is denied. Lost apply
responses can therefore be reconciled using the same plan ID; failed plans cannot
be used to retry deployment. Lifecycle actions are not plan-idempotent: query status
after uncertainty instead of automatically sending another restart/start/stop.
The request nonce remains distinct from the task ID.

No implicit service deletion/renaming is allowed on change. Update the complete
declaration with new pinned image digests, env/ports/mounts/resources, plan it, then
apply. Existing unused data directories are preserved. Host port availability and
other unmanaged Docker resources cannot be fully reserved at plan time; an external
conflict can still cause execution failure. Metadata is bounded to 10,000 plans and
10,000 tasks; at that bound the API fails closed and administrator archival is
required. There is no automatic data-directory cleanup.

## Failure and recovery

Tasks share the existing Runner `global.lock` with legacy deployments/actions.
Queued work survives restart. Task/status queries do not acquire that lock; enqueue
and plan may return `busy` while a deployment runs. Full policy and revision checks
run again before execution, so a queued task cannot use obsolete authorization.

Before `up`, start or restart, Runner persists a recovery guard. A failed partial
mutation leaves `recovery_required`; an interrupted running task becomes
`outcome_unknown` after restart and is **not replayed**. New deployment/start/restart
are blocked. Stop and observation remain available if permitted by root policy.
No failed operation claims data rollback. A failure before container mutation is
`failed`; newly created empty application directories may remain.

After external NAS recovery and application/data verification, an administrator
can clear a project's recovery flag **locally**, with Runner stopped, using the
root-only private workspace SQLite database. This pilot deliberately provides no
remote recovery-acknowledgement action. Restarting the engine alone cannot clear
the guard. Do not clear a guard while its task is running. Document the external
recovery decision before clearing it; restoring only an image is not DB recovery.

## Acceptance and AutoBangumi scope

CI tests closed-schema privilege rejection, stale plans, revisions, replay,
idempotent apply, cross-project resources/ports, queue persistence and failure
guards. Disposable Docker smoke exercises actual provisioning, health, lifecycle,
failed update, preserved media and unrelated-service uptime. Its local-image
adapter replaces registry pull/reference only and **does not verify production
registry/signature behavior**. Real DSM installation, ACLs, network rejection,
upstream image compatibility and AutoBangumi end-to-end download are **not yet
validated**. Existing Python tests and VPS success do not establish those facts.

AutoBangumi and qBittorrent can be represented as two services only after selecting
approved compatible images, actual application-readiness probes, UID/GID behavior,
directory access and exposure. Some images need Linux capabilities for their init
system; this pilot drops all capabilities and does not silently grant them. Such an
image needs another compatible image or a separately reviewed policy extension.
Subscription/downloader credentials and queue administration use the applications'
own authenticated APIs after deployment; this API has no generic file editor,
application-admin proxy, browser or terminal. Multi-image deployments are not atomic:
failure of one service may leave another updated, triggering external recovery.
