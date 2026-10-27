# Administrator-registered adoption transactions

## Decision

Add an opt-in server-owned registry, not remote Compose upload. Each exact project
registration holds a privately reviewed canonical JSON Compose declaration, its
hash, and the complete previously approved structural baseline. All image fields
must use the running image IDs, not mutable tags or new registry digests. Existing
project/service/container identity, mounts, networks and ports must match exactly.
The registry is root-owned and immutable to agents; only its path is in Runner
policy. No arbitrary caller paths, arguments, YAML or commands are accepted.

A transaction previews either observe-only adoption (no container change) or
redeploy (same reviewed declaration and same local image IDs). Both require their
own immutable Passkey approval, bound to registry/declaration/baseline hashes and
plan ID. Persistent grants may not float across baselines. Unpair/revocation and
policy drift are checked at enqueue and immediately before execution. Once grants
are atomically bound to a task by Approval, not consumed prematurely by reads.

Durable separate plan/task/ownership tables share the existing runner lock. Worker
validates exact Docker baseline, registry and canonical declaration again, records
a recovery guard before Docker mutation, then invokes fixed Compose argv with
explicit original project name, a private generated JSON file, no build/pull and
only the registered services. No original host Compose is parsed or executed.
Restart reconciliation marks running tasks outcome_unknown without replay. Failed
mutations require administrator recovery; failed preflight does not claim rollback.
Observe-only adoption retains container/image identity and records only ownership.
Redeploy retains all old image IDs, never cleans images/data, and requires approved
healthchecks plus real healthy states before success. No blank nonroot/cap-drop
policy is imposed on legacy image entrypoints. Root-capability behavior must be
explicitly reviewed in administrator configuration; privileged/host namespaces and
Docker socket mounts remain forbidden.

## Evidence and compatibility

The existing worker executes only the compiler namespace and cannot safely be
reused by swapping project prefixes. Existing Approval propose/check machinery is
usable, but exact transaction consumption needs a separate task binding. Docker
Compose up supports explicit project and file, --no-build, --pull never, --no-deps
and --wait; local image IDs are Docker image references. Tests must exercise actual
runtime JSON and preserved original project identity, not just mocks.

AutoBangumi moving latest may now resolve to v4. This mechanism never pulls it.
A future application-version/schema migration must be a separate approved plan;
reusing latest is not preservation of the running image. Application/root-entrypoint
compatibility and old schema state must be verified on-device before redeploy.

## Shared ingress

Shared ingress remains a different administrator-owned transaction boundary. Do
not mount Tailscale credentials into agents or join applications to the approval
namespace. Offline merge helper does not equal live apply. A dedicated local
application-ingress broker with independently provisioned Serve baseline is needed
before remote apply can be implemented safely; no caller-chosen Docker exec or
Tailscale socket path will be introduced as a shortcut.

## Rollout

Feature absent by default. Administrator locally creates and reviews registry using
bounded generator/validator and installs it read-only into Runner at a protected
path. NAS paths are never guessed. Engine upgrade, new inspection authorization,
real observation, local registration and transaction approval are distinct gates.
Tests cover cross-agent/project isolation, exact grant/task binding, revocation,
registry/baseline drift, bounded file handling, idempotency, recovery and no-pull.

## Implemented API and local registration workflow

Runner policy may opt in with adoption: {registry: /PROTECTED/targets.json} and
explicitly allow adoption_plan, adoption_request, adoption_apply, adoption_task.
These have /v2/adoption/plans, /requests, /apply, /tasks signed POST routes. Plan
payload is only action=observe|redeploy. Request/apply payload is only plan_id;
task payload is only task_id. No file path or Compose declaration is accepted.
Each plan is one hour; request always uses a once grant, bound uniquely to one
durable task. Bound grants remain visible and revocable; binding is not permission
to retry a task. Unknown/interrupted tasks are never replayed. Fresh apply requests
for an already-enqueued plan return its original task even after recovery latch.

Local administrator inputs are private JSON files, owner-only and no symlinks:

    python3 -m scripts.register_existing --baseline /PRIVATE/observation.json --reviewed-compose-json /PRIVATE/reviewed.json --output /PRIVATE/new-registry.json --allow-redeploy

The tool does not overwrite or install configuration. It creates a mode0600
registry with version=1 and targets keyed by exact original project. For existing
registries, administrator merges target entries and reruns validation privately;
do not overwrite other targets. Install registry root-owned0600 below protected,
non-symlink root-owned directories and mount read-only only into Runner. Synology
ACLs must deny untrusted writes to registry and ancestors; POSIX mode checks do not
prove ACL safety. Neither Gateway nor apps may access this private declaration.

Registration contains baseline, compose, declaration_hash, allow_redeploy and
health_timeout. Canonical compose permits a bounded set of service runtime fields,
exact original service/container names, local SHA image IDs, existing bind sources
with create_host_path=false, identical ports and existing external network names.
Named volumes, tmpfs, replication, custom command/entrypoint, privileged/host modes,
cap_add, unconfined security options, file references and interpolation are rejected.
Image-default root operation is not forcibly changed to nonroot. Administrator must
assess default image capabilities, entrypoint and host/network exposure before
approval. An image that requires added capabilities is not supported by this path.

Environment/user/restart/resource/probe/security settings are **approved changes**,
not verified preservation of the running runtime. Preview and approval explicitly
state this and bind the private declaration hash. Values stay private. An
administrator must compare original Compose/env privately; omitted custom runtime
settings may alter behavior, so incomplete reviews must not enable redeploy.
Meaningful fixed CMD healthcheck is mandatory for every redeployed service.

Same-image redeploy can recreate containers but never pulls or updates images.
Actual prior image IDs remain present; no automatic rollback or prune is run.
Generated reviewed JSON is placed in a private task directory with the original
project name passed explicitly. After recreation Compose config-file labels point
to that generated canonical file; old original Compose files are left intact.
This is a deliberate authority handoff, not a claim to preserve config-file labels
forever. A subsequent transaction requires fresh local registration of the new
baseline, preventing silent follow-up changes. Keep the old Container Manager
project stopped from making concurrent changes. A reviewed pre-existing downloader
and app settings are prerequisites, not discovered or configured automatically.

Current success means observe ownership was recorded or same-image registered
services reached their approved Docker healthchecks. It does not mean AutoBangumi
subscription/downloader/download acceptance, nor shared Tailscale Serve completion.
