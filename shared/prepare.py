"""One-shot setup of the deployer's own state and socket directories, run before the other services.

A directory created in File Station belongs to the DSM user, and the services run as root without
capabilities, so they could neither write it nor fix its mode (Tailscale insists on 0700 for its
state). This makes each directory root-owned with the mode its service expects. It only creates and
re-owns; nothing is deleted, so existing Tailscale identity and gateway data stay. Run as root with
CHOWN, DAC_OVERRIDE and FOWNER; idempotent."""
import os
import sys

# Relative to DEPLOY_ROOT. Nothing else under it (compose.yaml, .env, DSM ACLs) is touched.
DIRS = {'state/tailscale': 0o700, 'state/gateway': 0o700, 'run/tailscale': 0o755, 'run/runner': 0o755}


def own(path):
    info = os.lstat(path)
    if (info.st_uid, info.st_gid) != (0, 0):
        os.lchown(path, 0, 0)  # never follows a symlink


def prepare(root):
    for name, mode in DIRS.items():
        path = os.path.join(root, name)
        parent = os.path.dirname(path)
        for item in (parent, path):
            if os.path.islink(item):
                raise SystemExit(f'refusing symlink: {item}')
        os.makedirs(path, mode=mode, exist_ok=True)
        own(path)
        os.chmod(path, mode)
        # Files restored or copied in through File Station must be writable by the root service too.
        for top, dirs, files in os.walk(path):
            for entry in dirs + files:
                own(os.path.join(top, entry))
        print(f'{name}: root {mode:o}', flush=True)


if __name__ == '__main__':
    prepare(sys.argv[1])
