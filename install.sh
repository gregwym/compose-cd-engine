#!/bin/sh
# Run from the private deployment directory, not the engine source checkout.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
: "${CD_ENGINE_IMAGE:?Set CD_ENGINE_IMAGE to a verified digest}"
case "$CD_ENGINE_IMAGE" in *@sha256:*) ;; *) echo "engine digest required" >&2; exit 1;; esac
engine_digest=${CD_ENGINE_IMAGE##*@sha256:}
case "$engine_digest" in *[!a-f0-9]*) echo "invalid engine digest" >&2; exit 1;; esac
[ "${#engine_digest}" -eq 64 ] || { echo "engine digest must contain 64 hex digits" >&2; exit 1; }
signal_gid=${CD_SIGNAL_GID:-30001}
secret_gid=${CD_SECRET_GID:-30002}
case "$signal_gid:$secret_gid" in *[!0-9:]*|:*|*:) echo "numeric group IDs required" >&2; exit 1;; esac
[ "$signal_gid" != "$secret_gid" ] || { echo "group IDs must differ" >&2; exit 1; }
proxy_network=${CD_PROXY_NETWORK:-caddy_net}
docker network inspect "$proxy_network" >/dev/null
# Do not change existing application data or install example policies automatically.
install -d -o root -g root -m 0755 routes targets
install -d -o root -g "$signal_gid" -m 0750 sources candidates
install -d -o 10001 -g "$signal_gid" -m 0750 inbox
install -d -o root -g "$secret_gid" -m 0750 secrets
install -d -o root -g "$signal_gid" -m 2770 run
install -d -o root -g root -m 0700 state
[ -f secrets/scan-fingerprints.json ] || { echo "create private scan-fingerprints.json first (use [] if scanning is disabled)" >&2; exit 1; }
chown root:root secrets/scan-fingerprints.json
chmod 0600 secrets/scan-fingerprints.json
# Normal Compose merge discovers compose.override.yml for private application mounts.
docker compose config >/dev/null
docker compose pull
docker compose up -d
docker compose ps
