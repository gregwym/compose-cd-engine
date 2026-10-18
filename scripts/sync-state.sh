#!/bin/bash
# Host-only Git transport; never check out or execute remote repository code.
set -euo pipefail
umask 027
base=${CD_ROOT:-/opt/compose-cd}
: "${CD_PROJECTS:?Set CD_PROJECTS to a space-separated list of registry project IDs}"
signal_gid=${CD_SIGNAL_GID:-30001}
case "$signal_gid" in ""|*[!0-9]*) echo "invalid signal GID" >&2; exit 1;; esac
exec 9>"$base/state-sync.lock"
flock -n 9 || exit 0
export GIT_SSH="$base/bin/git-ssh"
git --git-dir="$base/state-repo.git" fetch -q origin '+refs/heads/*:refs/remotes/origin/*'
for project in $CD_PROJECTS; do
 case "$project" in *[!a-z0-9-]*|""|-*) echo "invalid project ID" >&2; exit 1;; esac
 branch="refs/remotes/origin/candidate-$project"
 git --git-dir="$base/state-repo.git" rev-parse --verify "$branch" >/dev/null 2>&1 || continue
 mkdir -p "$base/candidates/$project"
 for file in candidate.json candidate.bundle.json; do
  git --git-dir="$base/state-repo.git" show "$branch:$file" > "$base/candidates/$project/$file.next"
  if ! cmp -s "$base/candidates/$project/$file.next" "$base/candidates/$project/$file"; then mv "$base/candidates/$project/$file.next" "$base/candidates/$project/$file"; fi
 done
 chown -R root:"$signal_gid" "$base/candidates/$project"
 chmod 750 "$base/candidates/$project"
 chmod 640 "$base/candidates/$project/"*.json
done
work="$base/receipt-repo"
if [ ! -d "$work/.git" ]; then
 git init -q "$work"
 git --git-dir="$work/.git" --work-tree="$work" remote add origin "$(git --git-dir="$base/state-repo.git" remote get-url origin)"
 if git --git-dir="$work/.git" --work-tree="$work" fetch -q origin receipts 2>/dev/null; then git --git-dir="$work/.git" --work-tree="$work" checkout -q -B receipts FETCH_HEAD; else git --git-dir="$work/.git" --work-tree="$work" checkout -q --orphan receipts; fi
 git --git-dir="$work/.git" --work-tree="$work" config user.name 'Compose CD'
 git --git-dir="$work/.git" --work-tree="$work" config user.email 'compose-cd@users.noreply.github.com'
fi
cd "$work"
found=false
for file in "$base/state/"*.receipt; do
 [ -f "$file" ] || continue
 # Do not publish legacy receipts containing private filesystem paths.
 grep -q '"requested_images"' "$file" || continue
 cp "$file" "$work/$(basename "$file").json"
 found=true
done
for file in "$base/state/"*.deployed.json; do
 [ -f "$file" ] || continue
 cp "$file" "$work/$(basename "$file")"
 found=true
done
for file in "$base/inbox/"*.verification-status.json; do
 [ -f "$file" ] || continue
 cp "$file" "$work/$(basename "$file")"
 found=true
done
if [ "$found" = true ]; then
 git --git-dir="$work/.git" --work-tree="$work" add -- '*.json'
 if ! git --git-dir="$work/.git" --work-tree="$work" diff --cached --quiet; then
  git --git-dir="$work/.git" --work-tree="$work" commit -qm 'Record verified deployment results'
  git --git-dir="$work/.git" --work-tree="$work" push -q origin HEAD:refs/heads/receipts
 fi
fi
