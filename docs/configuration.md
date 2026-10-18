# Configuration and protocol v1

Policies are local administrator-owned JSON, never webhook-selected paths or
commands. See `examples/route.json`, `source.json`, `target.json`; the server-side
mount paths in Compose map them to `/etc/compose-cd/{routes,sources,targets}`.

A route fixes repository full name and numeric ID, approved workflow path/branch,
HMAC secret file and the verifier datagram socket. Relevant native workflow_run
completion signals contain only literal `check`. Authenticated irrelevant events
return 200; an accepted wake returns 202. Neither is a deployment-success result.

Sources support:

- `build`: approved **public** GitHub repository/workflow plus public GHCR image;
  current branch head must have a successful push/dispatch build, same-repository
  identity, signed index, source/revision OCI labels and selected platform digest.
  Private application builds/registry credentials are not implemented.
- `registry`: locally approved registry image/tag/platform plus Cosign-signed JSON
  and bundle in a per-project candidates directory. Add `tag` to source policy.
  The signing workflow identity comes from source `repository/workflow/branch`.
  The verifier independently fetches the exact manifest/platform after checking
  the signature. Docker Hub and GHCR are supported, not arbitrary registries.

The verifier writes only this candidate schema to the fixed inbox:

```json
{"schema_version":1,"project":"example-app","order":[100,1],"source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mode":"deploy","images":{"web":"ghcr.io/owner/example-app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
```

`order` is GitHub run ID / attempt, monotonic per target. Only `check` or `deploy`
mode is accepted. Targets require exact service/image repository allowlists and
fixed Compose directory/project/files; unknown candidate fields are rejected.
The runner does not accept a command, shell, path or target name from a request.

`observe` defaults to true. `snapshot_paths` must be existing root-owned
subdirectories below the Compose directory with distinct basenames.
`snapshot_exclude` names top-level entries that are excluded from snapshots,
rollback deletion and failed-state copies. Snapshotting pauses the selected
service; no global prune or volume deletion occurs. `healthcheck` is a fixed
local argv executed inside the selected container. `healthchecks` may override
per service; `tcp_checks` and `same_digest` support grouped service targets.
Scaled replicas are not supported. Public ingress and user workflows need their
own checks; a container health check does not prove them.

Receipts include project/run/revision, requested digest references, actual image
IDs, timestamps and exception class, not raw application logs or filesystem paths.
States include observed/checked/validated/deploying/success/no_change/failed/
rolled_back/rollback_failed. `<id>.deployed.json` keeps the last successful actual
deployment independently from subsequent check-only receipts. All receipts remain
private unless the operator explicitly reviews and publishes them.
