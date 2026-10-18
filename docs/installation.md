# Installation and engine upgrades

## Prerequisites

Linux, Docker Engine and Docker Compose v2 on the host, an existing reverse-proxy
Docker network, and an administrator who controls the Docker socket. Image Docker
CLI comes from the pinned Docker 28 CLI distribution; validate compatibility with
your daemon before adoption. Do not treat Docker socket access as rootless isolation.

Keep the private deployment directory separate from the engine checkout. Copy
`compose.yml` and `install.sh` into that directory. Runtime paths are relative to
this private directory. The source checkout and its Git history are not mounted.

1. Select a successful signed image build, obtain its immutable digest, and verify:

   ```sh
   cosign verify --certificate-identity 'https://github.com/kurisu-agi/compose-cd-engine/.github/workflows/engine.yml@refs/heads/main' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' ghcr.io/kurisu-agi/compose-cd-engine@sha256:REPLACE_WITH_DIGEST
   ```

   For tag releases use the exact `@refs/tags/v...` signing identity instead.
   Set `CD_ENGINE_IMAGE` to that approved digest in the shell or your private `.env`.
   The install script expects exported variables; it does not source `.env` as code.
2. Create private `routes`, `sources`, `targets` policies using `examples/*.json`.
   Examples use `observe: true`: no production changes until explicitly enabled.
   Keep policy files root-owned, not group/world-writable. Route secret files must
   be root-owned, use `CD_SECRET_GID` (default 30002) and mode 0440, with at least
   32 secret bytes; their containing directory must be group-traversable.
3. Create `secrets/scan-fingerprints.json`, mode 0600, root-owned: a JSON array of
   private literal patterns. Use `[]` only when target `privacy_scan` is false.
   Enabled scanning with an empty/missing list fails closed. Never commit patterns.
4. Add `compose.override.yml` with your target Compose directories mounted at
   their exact absolute paths in **runner only**. Mount Compose/config read-only,
   snapshot/restore data paths read-write. Mount every external bind source the
   host Compose CLI needs. Do not mount production data in receiver/verifier.
5. Review the rendered `docker compose config` privately. Run `sudo -E ./install.sh`
   from the private directory. The installer preserves existing configuration and
   never installs example policies or creates/replaces application volumes.
6. Proxy HTTPS `/hooks/<project>` to `compose-cd-receiver:18791` on the existing
   private proxy network. Do not expose the receiver's port directly. Register a
   GitHub repository webhook with application/json, the matching HMAC secret,
   TLS verification enabled, and Workflow runs events.
7. Application CI must publish `run-<run_id>-<run_attempt>` image tags, revision and
   source OCI labels, and keyless Cosign signatures from its approved workflow.
   For registry sources, configure a separate private signed candidate transport.
   Read the protocol document before enabling either source.
8. Verify observation, then set `observe: false` in source AND target policy and
   restart the engine roles to reload policies. Inspect actual terminal receipts.
   HTTP 202 only means accepted; it does not prove verification or deployment.

Custom signal/secret GIDs must differ and must be reserved for this deployment.
The receiver uses both, verifier uses only signal GID, and runner uses signal GID.

## Private registry-candidate and receipt transport

`scripts/sync-state.sh` is optional host-side Git transport, not an engine updater.
Configure `CD_ROOT`, `CD_PROJECTS` (space-separated registry target IDs) and
`CD_SIGNAL_GID`. Set up a private bare `state-repo.git` with an `origin`, plus a
host-only `bin/git-ssh` wrapper with strict host-key checking and a repository-only
deploy key. It fetches signed candidate branches as data and publishes sanitized
engine-produced receipts back to the same private origin; it never executes Git
content. Do not use it for a public state repository or feed arbitrary legacy
receipts into it. Build sources need no candidate Git transport. Run by your own
host scheduler if desired; the engine repository schedules nothing by default.

## Controlled engine upgrades

New engine images do not deploy automatically. Verify the new signature/digest,
review compatibility, save the old engine digest and privately back up policies
and state. Test the new image against an isolated target first. Quiesce pending
work before changing the image, update only `CD_ENGINE_IMAGE`, then recreate the
three engine roles. Leave business services/data untouched. Check source/target
loading, sockets, permissions, signed input verification and actual receipts.

Rollback the engine by restoring the previous digest and recreating engine roles.
A future incompatible state migration needs a separately documented migration and
backup; do not assume older engines can read a newer schema. Application rollback
is handled separately by the runner and retains excluded media.
