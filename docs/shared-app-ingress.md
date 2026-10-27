# Optional shared application ingress

This standalone, opt-in profile provides a **separate application Tailscale node**
for multiple administrator-registered backends. It does not migrate the existing
control node, adopt applications, update images, recreate applications or attach
the control plane to their network. It is not part of the GUI installer and is
not enabled by updating the engine image.

## Boundaries and transaction

- `app-tailscale` uses userspace networking on a verified application-only bridge.
  No host ports, TUN device, Docker socket or approval credentials are exposed.
- The unprivileged `app-proxy` shares only this application's network namespace.
  Fixed TCP relays bind **127.0.0.1**, not the bridge address. The root path,
  WebSocket upgrades and byte streams pass unchanged to fixed administrator DNS
  aliases and ports. Applications still need their own authentication and tailnet
  ACLs; the relay does not add application authentication.
- `ingress-broker` has **network_mode: none**, private journal state, the dedicated
  node's LocalAPI socket and the existing approval RPC socket/service key. It has
  no Docker socket or app data. This broker is privileged with respect to the
  dedicated Tailscale node; do not give it a control-node socket.
- Optional `ingress-gateway` runs in the existing management network namespace,
  listens on 127.0.0.1:18794 and forwards only signed `/v1/ingress` requests over a
  Unix socket. It has no service keys, approval state or LocalAPI socket. It does
  **not** install/change the control node's Serve configuration.
- Signed agent operations select only `backend` or immutable `plan_id`. No remote
  URL, host path, Compose, command, port or raw Serve document is accepted.
- Each apply/recovery requires a distinct **once-only Passkey approval**, exact
  policy/backend/baseline/candidate hashes and an active paired agent. Sandbox or
  persistent grants cannot authorize ingress. Unpairing/revocation is checked
  immediately before mutation. Original project adoption is separately approved.
- Existing unrelated Serve routes are preserved. Port conflicts, Funnel/public
  state, unsupported document fields and drift fail closed. Ports 443/8443 are
  reserved. This increment adds new routes only, not arbitrary route edits.
- Intent is committed before LocalAPI's ETag/If-Match compare-and-swap. Lost
  replies or interrupted writes latch `outcome_unknown`; never blindly replay.
  A fresh recovery plan and Passkey can restore the old document only from a
  recognized old/new state. Unrecognized drift needs administrator investigation.

## Administrator provisioning prerequisites

Use `compose.app-ingress.yml` as a **standalone project**, not an application or
control-stack overlay. Keep existing project names and Compose/.env intact.
Select an already verified local engine image (prefer a signed immutable digest).
No deployment step here authorizes an image pull or application recreation.

Choose an empty dedicated ingress root below an existing protected parent; set
`APP_INGRESS_ROOT` and its exact `APP_INGRESS_PARENT`. The `bootstrap` profile
initializes only this directory. It refuses unrelated content and repeat startup
preserves the existing policy and identity. All ancestor directories must be
root-owned and not group/world writable. On Synology, independently inspect ACLs;
POSIX mode checks cannot prove ACL protection. Do not mount a whole volume root.

The bootstrap policy is disabled. Review `policy/policy.json` locally as root:

```json
{
  "version": 1,
  "enabled": true,
  "hostname": "apps.example.ts.net",
  "agents": ["<existing-paired-agent-public-key-hex>"],
  "backends": {
    "example": {
      "dns": "app-example",
      "port": 8080,
      "local_port": 21001,
      "https_port": 9444
    }
  }
}
```

Use the new node's actual MagicDNS hostname and reviewed backend mappings, not
these examples. Ports must be unique; backend ports are 1024–65535, local relay
ports 20000–29999. Agent keys must already be paired in the approval service and
are independently allowlisted here. Policy changes invalidate pending plans;
restart the proxy after a reviewed backend-policy change.

`APP_INGRESS_BACKEND_NETWORK` must already be an application-only Docker network,
with the fixed `app-*` alias present. If an application is not on this network,
network attachment/recreation is a **separate reviewed application transaction**;
this profile does not attach it automatically. Never use the control bridge.

Provision/login the dedicated `app-tailscale` node interactively and approve its
ACLs/HTTPS certificate capability separately. No auth key is embedded in Compose.
The transport is deliberately gated to **Tailscale 1.104.2**; the profile pins
that version tag. Verify its platform digest before production installation.
The node must report Running and return a Serve ETag before planning is allowed.

Provide exact existing `APP_INGRESS_APPROVAL_RUN` and
`APP_INGRESS_APPROVAL_KEY` paths. The approval key remains root-owned and private;
set `APP_INGRESS_SECRET_GID` to its read group (default 30002) and
`APP_INGRESS_APPROVAL_GID` to the approval socket group (default 30004).
Broker socket group 30006 is shared only with the credential-free gateway.
No approval database is mounted. Check access using the actual cap-dropped UID/
groups; container UID 0 cannot bypass file modes when capabilities are dropped.

For the optional gateway profile, set the verified
`APP_INGRESS_CONTROL_CONTAINER` and exact `APP_INGRESS_MANAGEMENT_HOST` including
its HTTPS port. An administrator must separately merge a tailnet-only management
Serve mapping for `/v1/ingress` to 127.0.0.1:18794, preserving all existing routes.
Do not replace the full control Serve document or enable Funnel. The gateway
checks the forwarded Host. This wiring is not performed by the broker.

## Agent workflow

`scripts/app_ingress.py` uses the existing private Ed25519 key and system TLS
trust, rejects redirects and emits bounded JSON. Supply `--endpoint` (HTTPS
management origin), `--key` (owner-only PEM), then:

1. `plan --backend <registered-name>`: obtain immutable `plan_id` and hashes.
2. `request --plan-id <id>`: receive independent approval request. Review the
   dedicated ingress disclosure in the existing Passkey UI and approve once.
3. `apply --plan-id <id>`: execute only the approved CAS; inspect `status`.
4. `receipt --plan-id <id>`: retrieve durable result after a lost client reply.
5. For unknown writes, `recovery_plan --plan-id <original-id>`, then independently
   request/approve/apply that new plan. Do not resubmit the original mutation.

Plans expire after one hour. A successful apply is idempotent, but the receipt
records that operation's verified result, not ongoing route health. A policy,
application config, alias or tailnet ACL change needs renewed live acceptance.

## Evidence and rollout gates

Local tests cover signed requests/replay, real Passkey issuance, immutable scopes,
revocation, drift, journal recovery, Unix HTTP CAS and byte-preserving HTTP/
WebSocket relays. `scripts/test-app-ingress-network.py --image <local-image>`
uses disposable Docker networks to verify a nonroot loopback relay, isolation
from an independent control bridge, and absence of published ports/control
credentials. It neither joins a real tailnet nor mutates production apps.

Pinned upstream LocalAPI implementation confirms GET ETag, POST If-Match and
HTTP 412 on concurrent drift:
https://github.com/tailscale/tailscale/blob/v1.104.2/ipn/localapi/serve.go#L25

Still required on the actual host: signed engine/platform verification, protected
root/ACL inspection, node pairing and HTTPS certificates, backend identity and
network review, owner Passkey approval, authenticated app HTTP/WebSocket checks,
and real application workflow/download acceptance. Local tests and green CI are
not evidence that these production steps occurred.
