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
- Each owner decision is its own WebAuthn assertion with user verification,
  bound to a hash of the exact request row; a changed request cannot be approved
  with an old ceremony.

## Known limits

- An approved application image can still do whatever its own mounts and network allow.
- `network_mode: host`, extra capabilities, devices and host paths outside the project
  are allowed after review; read the highlighted items before approving.
- `env_file`, `include` and `extends.file` are read by the runner's Compose while rendering and
  are gone from the rendered configuration, so the hard policy cannot check their sources. The
  runner sees the deployer directory only as an empty tmpfs, so deployer state cannot be read this
  way, but other projects' files under `PROJECTS_ROOT` can; review those lines in the diff.
- Logs are returned to paired agents unredacted; applications that log secrets expose them.
- Restoring an old `state/gateway` backup can bring back revoked grants.
- Not independently audited.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for this
repository. Do not post credentials, host inventory or private configuration in
public issues.
