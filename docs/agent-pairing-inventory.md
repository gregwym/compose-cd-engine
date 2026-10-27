# Passkey pairing and read-only application inventory

## Decision

Pairing authenticates an agent; it does not authorize application access. An agent generates its own Ed25519 private key locally. Only its public key is sent to the NAS. The administrator compares the SHA-256 fingerprint and confirms the exact pairing request with a fresh Passkey ceremony. Requests expire after ten minutes. Device labels are untrusted text, not identity.

The separate inventory capability reveals deployed containers, including applications not created by deployer. It returns only project/service labels, container name, image and state. No environment, host paths, mounts, arbitrary labels, raw logs, Compose files or application data are returned. Results are capped at 64 containers and explicitly marked truncated when incomplete. Compose projects with no containers are not discoverable. Reading does not import or take over applications.

## Runtime

1. POST /agent/pair accepts a signed proof-of-possession request, not a browser session. Body limits, timestamps, persistent replay nonces and request-rate limits apply. Browser Origin requests are rejected.
2. The owner opens the returned pairing page, compares the fingerprint with the requesting machine, and approves with Passkey. Login alone cannot approve pairing.
3. V2 calls bind agent public key, identity, destination hostname, operation, payload, timestamp and nonce. Gateway and Runner verify independently. Runner checks the current approval-owned pairing registry.
4. An inventory_request for reserved project nas-inventory creates a separate once, expiring or persistent authorization request. The owner approves it with Passkey. Provisioning can remain disabled.
5. A live inventory grant is checked before the Runner executes a fixed read-only Docker query. A once grant is consumed before reading; read failure requires a new grant rather than blind replay. Lifecycle and provisioning paths remain separately protected.
6. Passkey disconnect revokes the paired identity, active grants and pending requests. Re-pairing does not revive old grants. A read already in progress may finish after revocation.

## Agent commands

Run from the repository root with PYTHONPATH=. and the pinned requirements installed. Use a client-owned directory of mode 0700; the generated PEM file is 0600. Never upload it or commit it.

    python3 -m scripts.pair_agent --origin https://APPROVAL_HOST --key-file /PRIVATE_DIRECTORY/agent.pem --label "My agent device"

The owner opens the returned URL and compares the fingerprint. Repeat with --status to check without creating another request. Then:

    python3 -m scripts.agent inventory_request nas-inventory --endpoint https://APPROVAL_HOST:8443 --secret-file /PRIVATE_DIRECTORY/agent.pem --mode persistent

After separate Passkey approval:

    python3 -m scripts.agent inventory nas-inventory --endpoint https://APPROVAL_HOST:8443 --secret-file /PRIVATE_DIRECTORY/agent.pem

Legacy configured HMAC agents remain compatible; no key copying or replacement occurs automatically.

## Existing Synology upgrade

No Compose layout change is needed. Pull/recreate engine services with the existing project Compose and .env. Preserve local Tailscale Auth key wiring. Do not replace configuration with an upstream example, reset state, or recreate Tailscale alone. Preserve existing Passkeys, approval state, service keys, Tailscale state and application data. Approval startup adds pairing tables without resetting identity. NAS backups remain administrator-owned; no snapshots, pruning, unrelated application recreation or automatic database downgrade are performed. Keep the previous image for recovery; use administrator restoration where needed.

Real NAS pairing, fingerprint comparison, inventory approval/read and revocation must be accepted after upgrade; local tests are not NAS acceptance.

## Evidence and tests

Existing transaction-bound WebAuthn lives in authorization/passkeys.py. Approval-only registry and inventory grants live in authorization/pairing.py and authorization/store.py. Independent signature checks are in authorization/agents.py, management/gateway.py and deployer/service.py. The fixed metadata projection is in deployer/inventory.py. Tests cover real software WebAuthn, signed HTTP-to-Unix dispatch, replay, audience/route binding, expiry, revocation, no implicit mutation rights and metadata filtering.

Primary references:
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
- https://docs.docker.com/reference/cli/docker/container/ls/
