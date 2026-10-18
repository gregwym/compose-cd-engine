# Security

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
