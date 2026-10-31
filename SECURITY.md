# Security

## Trust boundaries

- **runner** holds the Docker socket, which is equivalent to root on the NAS. It has
  no network and talks only to the gateway over a root-only unix socket. On every
  call it re-checks the project's Container Manager identity, the file hashes that
  were approved, and the hard policy in [design §6](docs/design.md#6-硬策略runner-独立执行).
- **gateway** has no Docker socket and no project files. It holds the only database
  (Passkeys, paired agent keys, requests, grants, jobs, triggers, audit). It decides
  who may act. If it is compromised, an attacker can operate projects within the
  runner's hard policy, but cannot mount the Docker socket, system paths or the
  deployer directory, or run privileged containers.
- **agents** hold only an Ed25519 private key. Requests are signed, bound to the
  gateway's name, time-limited and single-use.
- Owner request decisions require a WebAuthn-authenticated session and the exact
  displayed request binding. Account actions retain individual WebAuthn assertions.
  Changed requests cannot be approved with an old preview or ceremony.

## Known limits

- An approved application image can still do whatever its own mounts and network allow.
- `network_mode: host`, extra capabilities, devices and host paths outside the project
  are allowed after review; read the highlighted items before approving.
- `env_file`, `include` and `extends.file` are read by the runner's Compose while rendering and
  are gone from the rendered configuration, so the hard policy cannot check their sources. The
  runner sees the deployer directory only as an empty tmpfs, so deployer state cannot be read this
  way, but other projects' files under `PROJECTS_ROOT` can; review those lines in the diff.
- Bind and file sources are also checked after resolving symlinks, but only where the runner can
  see them (`PROJECTS_ROOT`). Elsewhere a host symlink to a forbidden path cannot be detected; such
  sources are highlighted with "symlinks not checked".
- A change preview that Compose rejects returns no Compose output, since an agent could put any
  existing `.env` value into an invalid field. Errors from approved operations are returned with
  `.env` values of four or more characters replaced by `***`; this is best effort.
- Logs require an explicit read or applicable project grant and use best-effort
  redaction. Applications can emit secrets not recognizable by the scrubber.
- Restoring an old `state/gateway` backup can bring back revoked grants.
- Not independently audited.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for this
repository. Do not post credentials, host inventory or private configuration in
public issues.

## Reusable grants (2026-10-29; supersedes legacy authorization sections)

Pairing authenticates an agent; it no longer implicitly grants environment reads.
Request kind=read, project=*, permanent=true for reusable environment-wide Docker
diagnosis, including the deployer itself. projects/logs/diagnose/read use allowlisted
Docker metadata, never arbitrary host files. Environment values, commands, health
output, arbitrary labels and driver options are omitted. Logs scrub known container
environment values and common credential patterns; arbitrary application-generated
secrets remain a best-effort limitation.

Request kind=manage for one immutable project identity with boundary JSON:
{"mounts":[{"path":"/volume1/media","mode":"ro"}],"networks":["shared-edge"]}.
Mount roots and sources must exist, be canonical and visible to runner; sources
must stay under an approved root without ro-to-rw escalation. new=true authorizes
a not-yet-created project under PROJECTS_ROOT, then request create deploys it.
Read/manage accept permanent=true, otherwise days=1..30 (default seven). Repeated
change/create/down under manage return jobs without approval. Lifecycle rechecks
boundaries too. Expansion requires a replacement manage request; out-of-bound
changes fail closed. Deployer self-management remains prohibited, self read allowed.

Project-owned default-named local volumes/bridge networks are supported; existing
resources must bear the exact Compose project label, not just a matching prefix.
Foreign/external volumes and custom names/drivers/options are rejected. External
networks must be named in the approved boundary; only attachment is permitted.
Reusable configs reject capabilities/devices, host/shared namespaces, privileged,
build, sockets, hooks/providers, security overrides, secrets/configs and file-loading
Compose features before rendering. A conservative lexical YAML gate rejects
escapes/tags/aliases and file-loader keys: deliberately a narrower Compose subset,
without a parser dependency. No down -v, prune or arbitrary Docker API is exposed.

Request kind=elevated, seconds=900 (1..3600; no permanent mode) after manage.
Elevation binds to the exact manage grant. exec takes project, full container ID,
argv array and timeout (1..120 seconds). No implicit shell, privileged exec or Docker
options are accepted; explicit shell argv is permitted within elevation, without a
command whitelist. Gateway rechecks agent and grants when the job executes; runner
rechecks project identity, live container mounts/privileges, boundary and expiry
inside its lock. Output is capped at 64 KiB with exit/timeout/truncation evidence.
Containers require GNU/BusyBox timeout. This mandatory in-container wrapper bounds
ordinary commands; malicious images/commands can fork/daemonize, replace timeout or
evade termination. This is NOT a hostile-code sandbox. Expiry/revocation prevents
new execution, cannot undo commands already started. Exec inherits app credentials
and network access. Replacing manage invalidates its elevation and linked triggers.

Migration adds scope/boundary columns idempotently; existing grants become legacy,
never manage/read. Existing one-shot requests retain semantics. Existing webhook
triggers retain narrower signer-pinned image-only updates. New triggers on managed
projects bind to the exact manage grant and recheck it before applying. Repository
numeric ID, branch/workflow signer, digest/revision and image-repository checks stay.
Authenticated matching webhook payload hashes are deduplicated for seven days.
Webhooks only wake polling; current branch head is resolved independently, so stale
delivery cannot select an old digest.

Pull triggers (`tag`, docs/design.md "Pull triggers") do not edit files. GitHub-sourced ones
require the workflow/branch Cosign signature on the tag's digest; registry-sourced ones trust the
upstream registry and tag, with no signature: approve them only for images you would update by
hand anyway. The runner checks the pulled image carries a verified digest before recreating. Files
identical to those approved with the trigger are not re-checked, so a project approved with
hard-policy violations (listed on the approval page) keeps being updated; any change to its
Compose files or `.env` brings the full check back. Files those load are not part of that
comparison. The optional public webhook listener serves only `/hooks/`, requires the per-trigger
HMAC and can only wake a check.

Gateway.public_preview(item) is the HTTP review contract for anonymous and owner
sessions: structural safe_diff from before/after rendered config, no raw compose,
diff, env values or job outcomes. Legacy requests without safe_diff show a withheld
placeholder and require resubmission for browser review. The allowlisted projection shows
images, ports, mounts, networks and lifecycle/security flags. Environment values,
commands, labels, healthcheck payloads and unknown fields are hidden. Known environment
values from both versions and common credential patterns are scrubbed from visible
fields. Resource names and paths are intentionally visible: do not put credentials
in names or paths. This is not a guarantee against arbitrary secret encoding.

The request link needs no login. Approval/denial requires an authenticated owner
session (15 minutes), same-origin CSRF checks, and the exact row binding returned
with the displayed preview. Snapshot and binding are read atomically; decisions
compare and update atomically. A changed, expired or decided request fails closed.
The first decision asks for Passkey login; an existing owner session is reused.
Pairing, revocation and other account actions retain their Passkey ceremonies.

Official references: Docker container exec CLI, Compose volumes/networks reference,
GitHub validating webhook deliveries/best practices. Explicit resource names are
not project-scoped, hence default-name AND ownership-label checks.
