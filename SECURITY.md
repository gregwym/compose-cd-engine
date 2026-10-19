# Security

## Agent-native authorization

The opt-in [v2 authorization model](docs/agent-authorization.md) separates agent
HMAC identities, administrator Passkeys and private Runner service credentials.
Only the trusted approval service issues/revokes grants, after transaction-bound
WebAuthn user verification or an explicitly administrator-preauthorized sandbox.
It never mounts Docker or application data. The Runner independently enforces
policy/grants at execution; enabling v2 rejects legacy project bypasses. Legacy
fixed targets require explicit disjoint administrator compatibility authorization.

Do not share service keys, local enrollment tokens, administrator sessions or
authorization SQLite files with agents. Restoring stale authorization backups
can resurrect revoked privileges; disable execution and reconcile revocations
before accepting a restore. Signed code with data access is still dangerous;
Docker socket access remains host-admin-equivalent. CI software authenticators
do not prove real iPhone, DSM ACL or production network compatibility.

Report vulnerabilities privately via GitHub Security Advisories for this repository
when available; do not put credentials, host inventory or exploitable production
configuration in public issues. This early-stage engine has not received an
independent security audit. Only the current main development line is maintained;
there is no stable/LTS promise yet.

Trust boundaries are described in README. The root runner has host-admin-equivalent
Docker access; network isolation does not reduce Docker socket authority. Anyone
who can edit local policies or the host daemon is trusted. Public application CI
may build/sign an image, but cannot choose host paths or arbitrary deployment
commands. HMAC is a wake-up authentication mechanism, not the sole approval for an
image. Signature provenance is checked independently against fixed source policy.

Keep secrets, policies, transport SSH keys, state and logs outside this repository
and image build context. Pin engine image digests after verifying the exact
workflow signing identity. Dependencies and Actions are pinned, not automatically
trusted forever. The bounded public-tree check is not a comprehensive secret scan.

## Optional management API

See [NAS trust boundaries and installation](docs/nas-management.md). Management
requests carry no Docker arguments, paths, image names, service selectors or shell.
The unprivileged HTTPS entrypoint and privileged action broker enforce independent
project/action allowlists. Nonce stores persist across restarts; never disable TLS
or expose this endpoint publicly. Raw log messages are withheld rather than
claimed safe through incomplete redaction. A compromised Runner still has full
Docker authority; a signed app image can access all app-granted data/networks.
NAS snapshots/backups and administrator recovery acknowledgements are not agent
operations. Pilot management targets disable tar snapshots and automatic rollback.
