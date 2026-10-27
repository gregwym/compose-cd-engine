# Opt-in registered task delegation

## Evidence and decision (2026-10-27)

At base 27669e0, authorization/store.py owns Passkey-issued grants, pairing and
revocation; deployer/transactions.py owns locked original-project transactions;
app_ingress/broker.py owns immutable fixed-backend Serve CAS plans and unknown
outcome latches. installer/initialize.py and app_ingress/init.py require local
administrator bootstrap. Neither an approval nor pairing installs host policy.
RFC 9396 sections 2 and 6.1 motivate structured resource/action authorization:
https://www.rfc-editor.org/rfc/rfc9396.html . This is not OAuth or RFC compliance.

Choose an explicit delegation ID on every supported request, rather than unioning
existing grants or loosening once-only transaction grants. Runner's administrator
policy adds a root-protected task registry; entries bind one project, exact agent,
canonical adoption registration hash, ingress policy hash, backend hash and route.
An owner sees a single expiring full-scope Passkey request. Approval validates
subplans against that exact grant. Delegated inspection is structural diagnostics
only (paths/images/mounts/ports/state), not logs/env/application data. Available
mutations are observe adoption, registered same-local-image redeploy, and fixed
registered tailnet ingress. Lifecycle/recovery/host installation are excluded.

Ingress plans remain immutable baseline/candidate CAS documents. Adoption plans
remain immutable except their task pointer; authority is checked at enqueue and
immediately before mutation. Separate immutable delegation receipts bind each
subplan/task; all consumers recheck live pairing, credential, expiry and revoke.
Policy/registry/backend changes fail closed. Expected post-redeploy runtime IDs
are accepted only through a successful worker-recorded exact new baseline; all
semantic identities (images/mounts/ports/networks/services/names) must match the
registered baseline. Preexisting unexpected runtime drift stays rejected.

Default APIs keep old schemas/authority absent explicit delegation_id. Task
registry is opt-in; callers cannot create it or upload YAML/env/commands/paths.
Recovery after unknown outcomes remains a fresh independent approval or local
administrator repair; no task scope implies recovery authority. Existing NAS
forbidden_by_policy is not bypassed. No NAS contacts or credentials are needed.

## Rollout and remaining host boundary

Administrator must install this engine, register reviewed original declaration,
enable the existing adoption operations plus delegation_request, and install a
root-owned 0600 task registry mounted read-only to Runner. Configure the separate
shared-ingress profile and application-only network/backend locally first. Add

task_delegation: {registry: /etc/compose-cd/task-delegations.json}

in Runner policy. Registry shape is version=1, targets={project: envelope}; see
authorization/delegation.py for exact envelope. No service auto-writes this file.
Policy/backend hashes must be computed from the validated in-container policies.
Review mount ACLs separately on NAS. Approval is not authority to self-bootstrap.
Image upgrades, new targets/mounts/routes, public exposure, data deletion, arbitrary
configuration, lifecycle and recovery all need separate owner/admin action.

CLI: python -m scripts.task_delegation --help. It executes explicit individual
stages, emits durable IDs, never automatically retries or requests extra grants.
Live NAS adoption and tailnet acceptance are not proven by local tests.

## Registry and client contract

Example root-owned task registry (replace hashes with local canonical fingerprints,
never paste private Compose/env into a public approval request):

```json
{
  "version": 1,
  "targets": {
    "autobangumi": {
      "agent": "agent-<paired fingerprint>",
      "registration_hash": "<sha256 canonical full adoption entry>",
      "ingress_policy": "<sha256 validated ingress policy>",
      "backend": "autobangumi",
      "backend_hash": "<sha256 backend entry>",
      "route": {
        "hostname": "apps.example.ts.net",
        "https_port": 9444,
        "root_path": "/"
      },
      "max_lifetime": 3600
    }
  }
}
```

POST /v2/delegation/requests uses the existing signed v2 principal/project
protocol, operation delegation_request and payload {lifetime: 3600}. Approval URL
uses the existing Passkey ceremony. The signed v2 grant_status for this exact registered-task request returns
delegation_id only while its matching Passkey grant, credential and pairing are
active and unexpired. That is the grant ID, not the request ID. Other request
status responses retain their old behavior. Every delegated inspect/adoption-plan/
adoption-apply explicitly supplies delegation_id. Plans store that ID immutably;
adoption-request is not needed and is rejected for a delegated plan. Existing
nondelegated requests keep separate once-only grants and are not implicitly
upgraded. Task status and receipts remain read-only and do not need extra grants.

The shared-ingress signed protocol accepts delegation_id AND project on plan and
apply; receipt remains plan_id only. Exact backend policy/hash/route are verified
by Approval. This supports adding the one registered route and idempotently
reading a successful apply; it does not edit an already-existing conflicting route.
Recovery plans deliberately omit task authority: fresh independent Passkey
approval or administrator repair is still required. Unknown results are terminal
for automatic execution, not permission to repeat a mutation.

Registry changes block Runner when its current envelope no longer equals approval;
Broker separately checks its own exact policy/backend and the same live grant.
To withdraw the entire combined task, revoke the central grant (do not rely on
editing only one component's registry). Unpairing and credential deactivation also
invalidate both consumers. Root registry edits are not grant revocation events.
Mount identity means exact Docker source/target/type/read-only projection, not
host inode/ACL attestation. No engine data-delete command is allowed; applications
with writable mounts can still modify their own data during normal operation.
Canonical private configuration is administrator-reviewed, not proven equivalent
to the running app's environment or application-level database schema.

### Local acceptance performed

Run full tests from the existing packaged image with source mounted /app read-only
and network none; root mode also exercises protected registry file tests. Run
scripts.smoke_task_delegation only with CD_DISPOSABLE_CI=1, root, and a disposable
Docker socket. It creates uniquely named fixture containers/network, uses a
software WebAuthn authenticator to approve ONE grant, performs structural access,
forces a real same-local-image health-only redeploy (checks new container ID),
accepts the worker-recorded expected baseline, and applies a SIMULATED Serve CAS.
It asserts unrelated container identity and single request/grant counts. Cleanup
removes only its own disposable fixtures. It does not prove live Tailscale ingress,
physical owner Passkey UX, NAS application/data compatibility, or NAS rollout.

Verification on 2026-10-27: 218 full root-container tests passed (no skips),
including signed Runner/Broker combined-path tests with one software Passkey
approval, revocation/expiry/unpair/credential deactivation, policy/registry/backend
mismatches, explicit opt-in/nonunion, interrupted/unknown recovery latches,
immutable subplans/receipts and post-redeploy semantic drift. The disposable real
Docker smoke passed; it verified changed container ID, unchanged local image and
unrelated container identity. Software Passkey and simulated Serve are explicit
limitations, not production acceptance.

Reproduce from this checkout (existing local image, no pull/publish):

```sh
docker run --rm --network none --user 0:0 -v "$PWD:/app:ro" -w /app \
  -e PYTHONPATH=/app:/app/tests --entrypoint python3 compose-cd-engine:ingress-test \
  -m unittest discover -s tests -v

docker run --rm --network none --user 0:0 -v "$PWD:/app:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock -w /app -e PYTHONPATH=/app:/app/tests \
  -e CD_DISPOSABLE_CI=1 -e CD_SMOKE_IMAGE=compose-cd-engine:ingress-test \
  --entrypoint python3 compose-cd-engine:ingress-test -m scripts.smoke_task_delegation
```


## Owner-held authorization continuation

To avoid asking the owner to send an “approved” message, start a bounded signed
poller before sending the emitted full-scope Passkey link. Example:

    mkdir -m 700 /private/path/task-state
    python -m scripts.task_delegation --endpoint https://runner.example.ts.net \
      --key /private/path/agent.pem --project existing-app request \
      --follow --state /private/path/task-state/grant.json \
      --lifetime 3600 --timeout 3600 --interval 5

The process emits an authorization_required event with the exact full scope,
approval URL, request ID, mode and lifetime. It polls only signed grant_status
for that request, then exits 0 with status=success, exact delegation_id and
resume state path. No task mutation, extra grant, renewal, callback or message
is performed. The completion owner must keep this process/result collection
owned, relay the approval link, then explicitly drive the granted task stages.
Do not promise a callback from this CLI. A successful result is a live check at
that instant, not a lease bypassing subsequent server checks.

Repeat the same command/state to resume after timeout or interruption. Restored
state retains the original lifetime even if CLI defaults differ; endpoint,
agent, project, request, plan, policy, full scope, mode and lifetime must remain
bound. Completed resumptions recheck the same live grant, not an unrelated grant.
The state includes private scope metadata (paths/identities), never private key
or Compose/environment values: keep its directory owner-only (0700); atomic
state and locking sidecar are 0600. Do not publish the state or scope events.
Only one owner may access a state at a time; use the same stable lock sidecar.
Timeout is 1..86400 seconds, polling interval 1..300 seconds (default 5).
Each HTTPS read has the existing 15-second transport timeout; an in-flight read
can finish beyond the polling deadline. Exit 75 means bounded timeout, pending,
backoff or retryable transport/local uncertainty; resume the same state. Three
consecutive status transport failures stop resumably. Retry-After/429 stops for
owner scheduling, never tight-loop retries. Exit 1 means terminal denial,
revocation, expiry, unpairing, invalid binding or unknown request outcome.
A lost request response/crash after durable request intent is terminal
outcome_unknown: never automatically create a replacement request. The owner
must reconcile that request independently. Without --state the legacy explicit
single request remains unchanged; --follow requires --state. Structural-only
inspect_request --follow remains a separate workflow, not task authority.
