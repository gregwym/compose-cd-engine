# Agent-native authorization (opt-in v2)

Implementation request: [issue #1, agent authorization](https://github.com/kurisu-agi/compose-cd-engine/issues/1#issuecomment-6260815018).

## Design and evidence

The existing `deployer/schema.py` compiles closed declarations, and
`deployer/service.py` owns durable plans/tasks, capacity reservations, locking,
readiness and crash guards. Existing `verifier/verifier.py` verifies signed OCI
indexes and resolves platform manifests without Docker access. These components
are extended, not replaced. No VM, external identity provider or database server.

The administrator-owned Policy is an absolute ceiling. An approval is a
project/agent-specific Grant, not permission to change Policy. The Runner
independently verifies the agent HMAC, recompiles the plan, and intersects the
current Policy with a live Grant before enqueue, dequeue, storage preparation,
and container mutation. A task records the particular Grant used; replacing it
does not resurrect a queued task authorized by a revoked Grant.

We use [python-fido2 2.2.1](https://developers.yubico.com/python-fido2/API_Documentation/_modules/fido2/server.html)
for [WebAuthn](https://www.w3.org/TR/webauthn-3/) verification, not custom
signature parsing. Dependencies are pinned with hashes. Challenges require user
verification, exact origin and RP ID, and bind an immutable server-side action,
request hash, browser session and expiry. Verification is separate from explicit
approval. A login assertion never approves a request. Synced passkeys with a
zero counter are supported; nonzero counters must increase.

### Reviewable implementation boundaries

* **P0:** isolated approval store/process; independent local enrollment; real
  WebAuthn verification; request/grant/audit persistence; independent agent
  authentication at Runner; revocation and queued-task enforcement; explicit
  legacy compatibility; signed provisioning pipeline; security regression tests.
  A minimal mobile approval page is included to exercise P0 without a dashboard.
* **P1:** resumable agent client; permission diff and scoped request lifecycle;
  persistent/once/expiring grants; administrator-preauthorized sandbox; Telegram
  notification/continuation instructions using the existing OpenClaw transport.
* **P2:** structured diagnostics, readiness/failure stages, safe reconciliation,
  bounded read retries, and retire-without-data-deletion. No automatic stateful
  rollback or arbitrary repair commands.

### Isolation and tradeoffs

An additional small approval process owns `authorization.sqlite`, credentials,
grants, ceremonies and append-only audit. It has **no Docker socket**, agent key,
project workspace, or application data. The Runner accesses only its private
Unix RPC with a distinct service key. This RPC can propose/check/audit, but has
no approve, credential enrollment or grant-edit method. Agent HTTP processes
never receive this service key or mount this socket directory.

An additional network-only provisioning verifier reuses the registry and Cosign
pipeline. It does not mount Docker or application data. Runner has no network.
The extra processes cost memory; their configured limits are 96 MiB and 192 MiB
(limits, **not measured resident consumption**). This is preferable to placing
WebAuthn or registry networking in the Docker-privileged Runner.

Grants conservatively bind the complete Policy hash. Any Policy edit requires
reauthorization; no permissive fallback. Persistent grants allow configuration
value changes and newer signed digests within the approved repository/workflow,
service names, environment keys, mount aliases/slots/targets, port mappings,
egress and per-service resource ceilings. Writable access includes equivalent
read-only access, never the reverse. Different grants are not implicitly unioned.
Unsigned exceptions in v2 require exact Policy digests **and** grant digests.

An optional `signed_index` in each service names a same-repository signed index;
Verifier proves that the declared exact platform digest belongs to it. Without
this field, the platform manifest itself must be signed. It checks the config's
OS/architecture, source label and commit revision independently. Services from
the same source must agree on source revision. Arbitrary release groups from
different repositories are **not** claimed atomic or mutually compatible.
Existing service sets cannot be silently reduced. Partial mutation latches
recovery, never restores data or reports a fictitious rollback.

For coordinated application images, the administrator may configure
`release_groups: [["app", "worker"]]`. If any named member is declared, every
member is required even on first creation; Verifier requires all members signed
from the same source and revision. Third-party databases can remain independently
pinned services outside this coordinated build group. Without such a trusted
group declaration, the engine cannot infer an upstream application's mandatory
service list; do not claim automatic completeness discovery. Deployment is still
not an atomic database transaction, even for a complete verified group.

## Administrator installation (manual, not performed by agents)

Start from the provisioning installation and same-absolute-path mounts in
[project-provisioning.md](project-provisioning.md). Merge
`compose.authorization.yml` after `compose.management.yml` and
`compose.provisioning.yml`. Keep the Runner's network disabled. The new services
publish no host ports. Configure a private HTTPS reverse proxy accessible only
through Tailscale; do not publish an approval daemon to the Internet. Test denied
network access, not just DNS resolution. The proxy must preserve the public
`Host` header and reject unapproved origins. WebAuthn requires a stable HTTPS
hostname (not an IP). The example requires `origin` hostname **equal** to `rp_id`.

Copy and edit:

* `examples/agent-deployer-policy.json` → administrator-owned provisioning Policy
  (`enabled` remains false until installation acceptance).
* `examples/agent-gateway.json` → management gateway configuration.
* `examples/approval-policy.json` → approval service configuration.

All policy files/ancestors must be root-owned and not group/world-writable. On
the trusted host console, create **three different random keys**, at least 32
bytes each: agent HMAC, approval RPC, verification RPC. Do not use the webhook
key for these roles. Provision with a trusted administrator tool; avoid shell
history or printing values. Files must be root-owned 0640, groups respectively
30002, 30004, 30005 (or matching configured GIDs). Agent-key directory must be
root-owned and non-writable to those readers. Only the agent HMAC key is copied
to OpenClaw, as its private 0600 credential. Never send RPC keys, enrollment
tokens or administrator sessions through OpenClaw.

Required directories (administrator creates them before Compose starts):

| Directory | Owner:group | Mode | Mounted into |
|---|---|---|---|
| approval-state | 10004:30004 | 0700 | approval only |
| approval-run | 10004:30004 | 0750 | approval writable; Runner read-only |
| verification-state | 10005:30005 | 0700 | project-verifier only |
| verification-run | 10005:30005 | 0750 | project-verifier writable; Runner read-only |
| provisioning workspace | root:root | 0700 | Runner only |

Socket entries are 0660 in these dedicated directories. Do not mount them into
management, receiver, applications, or the old verifier. Service keys must not
match any agent key. Keep the existing fixed-target verifier/inbox separate.
Configure platform `linux/amd64` on DS923+; verify the actual Docker platform.

### Enrollment, removal, and recovery

From an independent trusted administrator console (not OpenClaw), run the
approval container command `python3 -m authorization.server --bootstrap owner`
with its existing policy/state mounts and UID. It emits a single-use 10-minute
enrollment code. Open the private HTTPS `/enroll` page directly in Safari, enter
the code, and create a platform Passkey using Face ID. The server stores only
public credential data and counters. Every new credential needs another local
bootstrap code. There is no public self-registration.

Sign in with Passkey, inspect server-supplied permissions, then approve with a
**new** Passkey ceremony. Denial, revocation and credential removal also require
fresh verification. The last credential for an administrator cannot be removed
through the browser. Adding a recovery credential requires local bootstrap.
Cookies are Secure/HttpOnly/SameSite=Strict, expire in ten minutes and disappear
across process restarts. Ceremonies are persisted for two minutes and consumed
once, including failed verification. Origin/Host/CSRF checks protect POSTs; CSP
disallows framing/inline scripts. Links identify requests, not bearer authority.
Anyone holding an approval URL still needs an enrolled administrator Passkey.

Back up approval SQLite state and provisioning workspace **outside agent
authority**, with the engine stopped for a consistent administrator-controlled
copy or SQLite's backup API. Keep Policy, service keys and origin configuration
in the trusted administrator backup. Passkey private keys never enter this
backup. Restore both authorization and task state consistently; restoring an old
authorization DB can resurrect revoked grants, so reconcile revocations and
disable execution until the administrator has reviewed restored state. Changing
the RP hostname requires re-enrollment. Loss of all Passkeys uses local bootstrap,
not an agent recovery endpoint. Engine code does not manage NAS snapshots.

## Compatibility and migration

Without `authorization`, legacy v1 provisioning/CD is unchanged. This does not
silently upgrade a legacy installation's security guarantees. Enabling
authorization rejects all direct v1 project operations at Runner, not only HTTP.
Old unowned projects/queued tasks cannot be adopted or executed through a v2
fallback. Quiesce and complete the old queue before enabling v2; prepare an
administrator-reviewed recreation/migration with independent data recovery.
Do not delete old databases to bypass a migration failure.

With `CD_AUTHORIZATION_REQUIRED=1`, every fixed legacy target requires explicit
administrator `legacy_authorized: true`, and its Compose project may not use
the reserved `cdp-` prefix. Fixed-target config remains read-only. The gateway
also requires `legacy_compat: true` before exposing configured v1 management
targets alongside agents. This is an explicit, separate, fixed compatibility
authorization, not authority over dynamic projects. Leave unneeded legacy
targets absent. No production policy is edited automatically.

Revocation blocks new work and is checked again for queued work and immediately
before container mutation after long pulls. Work already executing at the
revocation linearization point is not forcibly interrupted; revocation never
implicitly stops containers or deletes data. A once Grant binds one plan; the
durable plan→task mapping prevents repeat execution. Unknown outcomes remain
guarded across restart. No automatic retry of an unknown lifecycle operation.

## API transport

Machine-readable request schemas and endpoints: [OpenAPI v2](openapi-v2.json).
Policy-dependent restrictions are stricter than generic JSON schema limits.

Agent calls use POST for reads as well as mutations so the existing HMAC scheme
can bind exact body bytes, identity, request nonce and timestamp without query
canonicalization ambiguities. This is a deliberate refinement of the suggested
REST endpoint names. Every request has:

```json
{"version":2,"agent":"openclaw","project":"app","operation":"plan","request_id":"32 lowercase hex characters","timestamp":1792390000,"payload":{"services":{}}}
```

The signature is `X-Management-Signature: sha256=<HMAC-SHA256 exact body>`.
Gateway **and Runner** validate the principal's key and reserve durable nonces.
Requests are limited to 60,000 bytes, ±60 seconds; no redirects or arbitrary
Compose/YAML. Browser approval endpoints use Passkeys, never agent HMAC.

| Agent POST route | Operation | Payload |
|---|---|---|
| /v2/plans | plan | closed declaration, optional egress boolean |
| /v2/grant-requests | grant_request | plan_id, mode: once/persistent/expiring, lifetime: seconds |
| /v2/grant-requests/status | grant_status | approval_id |
| /v2/grants | grants | {} (project-scoped) |
| /v2/deployments | apply | plan_id |
| /v2/tasks | task | task_id |
| /v2/projects | projects | {} (agent-owned projects only) |
| /v2/projects/status | status | {} |
| /v2/projects/diagnose | diagnose | {} |
| /v2/projects/start, /stop, /restart, /retire | corresponding operation | {} |

Plans return `authorized` or `needs_approval`, with `grant_diff`, or a bounded
failure category. Requests include `request_id`, `approval_url`, scope, mode,
policy/spec hashes. No environment values or host storage paths are returned.
`once` expires with the request; `expiring` starts its lifetime on approval;
`persistent` has no expiry. Plan validity is still one hour. Admin UI endpoints
are `GET /api/data` (authenticated grants/requests/credentials/audit), and
`POST /api/begin`, `/api/finish` for transaction-bound ceremonies. They are not
agent endpoints; forwarding `approved: true` never authorizes anything.

## OpenClaw / Telegram continuation

Use the existing OpenClaw Telegram conversation, not another bot or a chat-based
approval credential. Install only the project agent HMAC key on the Mac in a
0600 file. No Passkey, administrator cookie, enrollment code or service key is
needed by this client. Run from the repository root with `PYTHONPATH=.`:

```sh
python3 scripts/agent.py deploy autobangumi --agent openclaw \
  --endpoint https://engine.example.ts.net --secret-file /private/path/agent.key \
  --spec /private/path/autobangumi.json --state /private/path/autobangumi-flow.json \
  --mode persistent --follow
```

The state directory must be owned by the agent user and mode 0700; specification
and key files must be 0600. Use a new state filename for a new deployment. To
resume the same flow after a restart, repeat with the **same state file**, with
`--spec` optional. A supplied spec must match its original hash; the client will
not silently re-plan a changed deployment after approval. Changing endpoint,
project or agent is also rejected. The state contains IDs/hashes, never spec
environment values or credentials.

OpenClaw should start this command as a background-capable tool invocation and
read its JSON lines. On `authorization_required`, send the current Telegram
conversation a concise server-supplied scope summary and the returned HTTPS
`approval_url`. Example:

> AutoBangumi requests read/write access to the approved downloads alias, an
> approved image workflow, and the shown resource/network limits. Review and
> approve with Passkey: [Open private approval page](https://deployer.example.ts.net/).
> Chat replies do not authorize this request. Open in Safari if necessary.

Keep the command running: it polls authenticated grant status and, after
approval, applies the **original plan**, then follows its durable task. It does
not require another chat message or copy an administrator session into OpenClaw.
If the process or OpenClaw restarts, resume from the same state file. Exit 75
means pending/temporarily unavailable; schedule a resumed invocation, not a new
deployment. Deduplicate notifications by `request_id`; do not notify on every
poll. Denial/expiration/stale policy are reported, not bypassed or reauthorized
by the agent. A plan still expires after one hour even for a persistent Grant.

`scripts/agent.py` also exposes individual plan/apply/task/status/lifecycle
operations. It never automatically repeats an unknown start/stop/restart/retire.
Workflow transport retries are bounded and limited to read calls and the
idempotent request/apply mapping for the exact same plan. Success is reported
only after the engine's durable task says success.

### Administrator-preauthorized disposable sandbox

Optionally add an `authorization.sandbox` profile to the administrator Policy:

```json
{"repositories":["ghcr.io/example/app"],"memory_mb":128,"cpus":1,"max_services":1}
```

Every repository must require trusted signatures. A declaration qualifies only
when it has no mounts, no published ports, egress disabled, and fits those
service/resource ceilings. This profile is the human's prior authorization;
the Runner requests a policy-attributed, audited Grant without a Passkey. This
is not agent self-approval. Adding a mount, port, unsigned digest or egress no
longer qualifies and needs a fresh explicit human request, if Policy permits it.
Containers still share the host kernel; this is not a VM security boundary.

## Residual risk and validation boundary

### Restricted operational behavior

Diagnostics expose only known service lifecycle state, exit code, bounded
restart count, health/readiness, numeric memory/CPU percentages and the last
task's enumerated failure stage/category. No free-form health output, logs,
environment variables, mount paths, argv, arbitrary inspect JSON or application
data are returned. Diagnostics themselves require a matching Grant operation.

`retire` requires its own approved operation. It stops/removes only containers
selected by the project namespace, without Docker's volume-removal flag. It
retains bind-mounted application data, grant/audit/history and network metadata.
Retired resources cannot be silently restarted; an authorized new apply is
required. This is resource cleanup, **not deletion of an application's data**.
The engine does not prune unrelated networks/images/volumes or administer backups.

Crash reconciliation changes in-flight mutations to `outcome_unknown` and keeps
the recovery guard. Audit delivery uses a durable local outbox and idempotent
insertion into the administrator's audit database, including unknown outcomes.
There is no general automatic stateful repair or database downgrade. Read-only
polls and exact-plan idempotent request/apply may be retried within client limits;
a failed preflight can use a new plan after the actionable problem is resolved.
The engine does not retry partially applied stateful work.

Plan results distinguish `invalid_configuration`, `forbidden_by_policy`,
`insufficient_resources`, `needs_approval`, `authorized`, `stale_request`, and
`recovery_required`. Detailed internal exceptions remain withheld.

Runner's Docker socket remains **host-admin-equivalent**. Grant checks constrain
inputs, not a compromised Runner or approval process. Signed agent-controlled
code with writable NAS mounts can corrupt data, and with egress can disclose it.
Signing is not a replacement for data isolation. No arbitrary capabilities,
host mounts, Docker API, DSM access, shell, backup/snapshot access or privileged
containers can be requested through v2. Network permissions currently expose
only isolated project networking, bounded published mappings, and an egress
boolean; unsupported per-destination rules/capabilities are rejected, not faked.

Software-authenticator tests perform real ES256 signature verification but do
not demonstrate Safari/Face ID compatibility on a physical phone. Docker CI is
disposable and does not demonstrate DSM ACL, private-network rejection, memory
usage or application integration. Before NAS acceptance, manually verify those
properties, real Passkey enrollment/approval/revocation, persistent state across
restarts, AutoBangumi/downloader readiness and preserved disposable media. Do
not attach real media/photos/backups to make automated tests pass.

For a repeatable mobile UI check, install Playwright only in a development
environment, install its Chromium browser, and run
`PYTHONPATH=. python3 scripts/smoke_approval_browser.py`. It uses a disposable
localhost TLS certificate and Chromium's virtual authenticator for genuine
browser registration/assertion ceremonies, review/approval and revocation.
It does not enroll an owner credential or test physical Safari/Face ID.
