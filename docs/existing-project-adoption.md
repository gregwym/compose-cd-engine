# Existing-project adoption and shared ingress: staged implementation

## Decision and current boundary

Do not rename an existing project into the provisioning namespace, reconstruct
Compose from Docker inspect, or execute arbitrary uploaded Compose. Those options
would lose original environment/interpolation semantics and bypass the closed
compiler. Preserve original project name, ordered config files, working directory,
mounts, actual image IDs and administrator-owned backups. No engine snapshots,
media manipulation, recursive ownership changes, down, prune or automatic database
downgrades are introduced.

The structural layer provides separately authorized discovery and offline preview
helpers. The next layer now implements administrator-registered observe adoption
and exact same-local-image redeploy; see [execution design](adoption-execution-design.md).
No unreviewed original Compose is executed. Shared ingress apply and actual NAS
migration remain unaccepted; these features do not establish AutoBangumi readiness.

## Verified evidence

- Existing compiler: deployer/schema.py accepts a closed declaration and renders
  isolated project networking; it deliberately rejects arbitrary YAML, commands,
  external networks and namespace joins. Existing tasks use a reserved namespace.
- Pairing/inventory: authorization/pairing.py authenticates identities independently
  from grants. An inventory grant exposes neither mount paths nor management.
- Docker supports field-projected inspect templates:
  https://docs.docker.com/reference/cli/docker/inspect/
- Tailscale Serve supports HTTPS ports, tailnet-only reverse proxy and status JSON:
  https://tailscale.com/docs/reference/tailscale-cli/serve
  The documentation specifies local proxy backends (127.0.0.1). A Docker service
  name on a different bridge is not automatically a supported local backend.
  set-config/get-config concern Tailscale Services; this increment does not confuse
  that schema with the device Serve JSON used by the existing installer.

## Shipped API

Signed v2 POST /v2/projects/inspect-requests (operation inspect_request) accepts
only mode and lifetime. The project is one existing Compose project, not a
caller-selected path or container ID. Owner Passkey approval lists that exact
project and explicitly discloses that host paths become visible. Pairing and
inventory authorization alone cannot authorize this read. Once, expiring and
persistent grants retain existing revocation/unpair semantics.

Signed POST /v2/projects/inspect (operation inspect) consumes/checks the independent
grant before Docker access, even with provisioning disabled. Runner filters by the
exact Compose project label, validates full IDs and obtains an explicit projection:
container/name/service/image/image ID, Compose config-files/working-dir labels,
mount source/target/read-only, published ports, network names, state. Config.Env,
other labels, healthcheck output, logs and app files are not returned. No host file
is opened. Host paths and network names are sensitive structural metadata: store
responses privately, never in public issues or test fixtures.

Output is bounded before subprocess buffering (512 KiB per command), per projected
container (32 KiB), container count (32), and final baseline (48 KiB). Structural Docker queries share
a six-second total deadline, with remaining timeout passed into every subprocess;
inspection authorization RPC is capped at two seconds. Unsupported,
missing or inconsistent metadata fails closed. Membership is rechecked after the
projection, but this is not a Docker transaction: baseline hash is an observation,
not a guarantee against same-ID metadata changes during collection. A future
mutation must fully revalidate under the runner lock immediately before execution.

CLI (placeholder origin and private key path):

    python3 -m scripts.agent inspect_request existing-app --mode once --endpoint https://MANAGEMENT_HOST:8443 --secret-file /PRIVATE_DIRECTORY/agent.pem
    python3 -m scripts.agent inspect existing-app --endpoint https://MANAGEMENT_HOST:8443 --secret-file /PRIVATE_DIRECTORY/agent.pem

Existing NAS installations require an engine upgrade before these routes exist;
current inventory permissions do not change during upgrade. No owner credentials
are transferred to the agent. Empty legacy agents dictionaries are now accepted
for Ed25519-only use; the existing policy structure still requires the dictionary.

## Offline preview helpers (not apply APIs)

adoption_preview validates the observation hash and rejects ambiguous Compose
identities or replicated services. It reports preserve-identity/mount/image
invariants and execute_allowed=false. It cannot grant or execute adoption.

The ingress planner merges one new root-path HTTPS-port route into an explicit
Serve baseline and hashes baseline/candidate. Existing routes are preserved,
443/8443 and control-plane upstream ports are reserved, Funnel-enabled baselines
and route conflicts are rejected, and targets must come from an administrator
allowlist of loopback HTTP ports. Reconcile rejects baseline/candidate drift.
It is an offline helper, not a credential-bearing Tailscale control channel.
A dedicated shared application ingress must first provide the selected backend
inside its network namespace. Per-app sidecars and joins to the deployer approval
namespace are not generated. Neither are guessed public app URLs.

## Remaining implementation and rollout gates

1. Upgrade the engine preserving original Compose project/config/env, Passkeys,
   approval DB, all service keys and Tailscale identity; independently verify build.
2. Obtain separate per-project inspection approval and read the real baseline.
3. Administrator locally reviews original Compose and environment privately.
   Docker labels are untrusted hints, not permission to open arbitrary host files.
   A safe adopter requires a server-owned exact target registration plus canonical
   reviewed declaration/hash, bounded trusted file handling and execution policy.
4. Install the opt-in administrator registry, then approve the immutable adoption
   transaction. Existing-project durable tasks enforce exact baseline/policy/hash
   revalidation and same local image IDs; partial failure latches recovery-required.
5. Provision shared app ingress with reviewed network isolation and meaningful
   backend probes. Add independent ingress grants, control-plane separation,
   drift reconciliation, durable apply/receipt and tested recovery. This increment
   does not edit existing sidecar or proxy configuration.
6. Validate selected upstream image version/entrypoint UID and permissions, existing
   app config/data compatibility and actual downloader dependency. A running image
   with a moving tag does not establish its release version or readiness.
7. Prove homepage and protected API behavior, application health, downloader
   authentication and a permitted end-to-end download separately. Preserve all
   unrelated container identities and starts. NAS testing remains mandatory.

## Tests and risk

Unit tests cover separate grants, once consumption, project binding, pairing,
project/membership drift, sensitive field exclusion, bounded child-process output,
reserved ingress targets, merge preservation, conflicts and drift reconciliation.
Disposable Docker smoke validates the real template projection; no production
container or app is changed by local tests. This increment has no new mutation
surface; it still reveals explicitly approved host structure and inherits Docker
socket host-admin-equivalent risk in Runner. Approval remains socket-free.
