#!/bin/sh
# First deployment of synology/compose.yaml with the image tagged as its `image:`.
# Cases: an empty DEPLOY_ROOT, and one whose directories a DSM user made in File Station.
# Usage: tests/first_deploy.sh empty|dsm   (as root)
set -eu
case="$1"
repo=$(cd "$(dirname "$0")/.." && pwd)
root=$(mktemp -d)
deploy="$root/deployer"
mkdir -p "$deploy" "$root/projects"
cp "$repo/synology/compose.yaml" "$deploy/compose.yaml"
printf 'DEPLOY_ROOT=%s\nPROJECTS_ROOT=%s\n' "$deploy" "$root/projects" > "$deploy/.env"
if [ "$case" = dsm ]; then
  for d in state/tailscale state/gateway run/tailscale run/runner; do mkdir -p "$deploy/$d"; done
  echo restored > "$deploy/state/gateway/old-file"
  chown -R 1026:100 "$deploy"
  chmod -R 777 "$deploy"
fi
project="first-deploy-$case"
cleanup() { docker compose -p "$project" --project-directory "$deploy" down --remove-orphans >/dev/null 2>&1 || true; rm -rf "$root"; }
trap cleanup EXIT

docker compose -p "$project" --project-directory "$deploy" up -d
sleep 20
docker compose -p "$project" --project-directory "$deploy" ps -a
logs=$(docker compose -p "$project" --project-directory "$deploy" logs --no-color)
echo "$logs"
# Tailscale keeps running when its state directory is unusable, but loses its identity on restart.
if echo "$logs" | grep -E 'in-memory store|chmod .*not permitted'; then echo 'Tailscale state is not persistent'; exit 1; fi

test "$(docker inspect -f '{{.State.ExitCode}}' "$project-prepare-1")" = 0
for s in tailscale gateway runner; do
  test "$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' "$project-$s-1")" = 'running 0' \
    || { echo "$s is not running steadily"; exit 1; }
done
test "$(stat -c '%u:%g %a' "$deploy/state/tailscale")" = '0:0 700'
test "$(stat -c '%u:%g %a' "$deploy/state/gateway")" = '0:0 700'
test "$(stat -c '%u:%g %a' "$deploy/run/runner")" = '0:0 755'
test -S "$deploy/run/runner/runner.sock"
if [ "$case" = dsm ]; then
  test "$(cat "$deploy/state/gateway/old-file")" = restored
  test "$(stat -c '%u' "$deploy/compose.yaml")" = 1026  # the project's own files keep their owner
fi
# Redeploying runs prepare again and keeps the Tailscale identity.
key=$(sha256sum "$deploy/state/tailscale/tailscaled.state")
docker compose -p "$project" --project-directory "$deploy" up -d --force-recreate
sleep 10
test "$(docker inspect -f '{{.State.ExitCode}}' "$project-prepare-1")" = 0
test "$(sha256sum "$deploy/state/tailscale/tailscaled.state")" = "$key"
echo "first deploy ($case): ok"
