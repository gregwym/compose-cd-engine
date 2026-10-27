"""Idempotent, root-only initialization of one dedicated installation directory."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat

DIRECTORIES = {
    'config': (0, 0, 0o755),
    'config/management': (0, 0, 0o755),
    'config/provisioning': (0, 0, 0o755),
    'config/approval': (0, 0, 0o755),
    'config/tailscale': (0, 0, 0o755),
    'config/targets': (0, 0, 0o755),
    'config/agent-keys': (0, 30002, 0o750),
    'config/service-keys': (0, 0, 0o755),
    'config/service-keys/management': (0, 30002, 0o750),
    'config/service-keys/approval-service': (0, 30004, 0o750),
    'config/service-keys/verification-service': (0, 30005, 0o750),
    'state': (0, 0, 0o755),
    'state/runner': (0, 0, 0o700),
    'state/workspace': (0, 0, 0o700),
    'state/management': (10001, 10001, 0o700),
    'state/approval': (10004, 30004, 0o700),
    'state/verification': (10005, 30005, 0o700),
    'state/tailscale': (0, 0, 0o700),
    'runtime': (0, 0, 0o755),
    'runtime/management': (0, 30003, 0o750),
    'runtime/approval': (10004, 30004, 0o750),
    'runtime/verification': (10005, 30005, 0o750),
    'runtime/tailscale': (0, 0, 0o700),
    'apps': (0, 0, 0o755),
    'apps/config': (0, 0, 0o755),
    'apps/downloads': (0, 0, 0o755),
}


def check_regular(path, mode=None, gid=None):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
            or info.st_mode & 0o022 or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or (gid is not None and info.st_gid != gid)):
        raise ValueError('unsafe installation file: ' + str(path))


def create_file(path, content, mode=0o644, gid=0):
    """Never truncate existing files or follow links, including dangling links."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        check_regular(path, mode, gid)
        return False
    with os.fdopen(fd, 'w') as target:
        os.fchown(target.fileno(), 0, gid)
        os.fchmod(target.fileno(), mode)
        target.write(content)
        target.flush()
        os.fsync(target.fileno())
    return True


def json_file(path, value):
    return create_file(path, json.dumps(value, indent=2) + '\n')


def deployment_root(value):
    if not isinstance(value, str) or not value:
        raise ValueError('DEPLOY_ROOT must be the absolute host project directory')
    path = PurePosixPath(value)
    if (not path.is_absolute() or str(path) != value or str(path) == '/' or value.startswith('//')
            or '..' in path.parts or any(ord(c) < 32 or c in '$:\\' for c in value)):
        raise ValueError('DEPLOY_ROOT must be a normalized absolute Linux path without trailing slash or shell/Compose metacharacters')
    for prefix in ('/etc', '/proc', '/sys', '/dev', '/run', '/var/run', '/var/lib/docker', '/usr', '/bin', '/sbin', '/lib', '/root'):
        if value == prefix or value.startswith(prefix + '/'):
            raise ValueError('DEPLOY_ROOT cannot be a host system/control directory')
    if re.fullmatch(r'volume[0-9]+', path.parts[1]) and (
            len(path.parts) == 2 or path.parts[2].startswith('@')):
        raise ValueError('DEPLOY_ROOT cannot be a Synology volume root or system directory')
    return value


def initialize(root, host_root):
    host_root = deployment_root(host_root)
    if os.geteuid() != 0:
        raise ValueError('initializer requires container root')
    root = Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('installation root must be a real directory')
    marker = root / 'installation.json'
    if marker.exists() or marker.is_symlink():
        check_regular(marker, 0o644, 0)
        if json.loads(marker.read_text()) != {'schema': 1, 'host_root': host_root}:
            raise ValueError('installation schema/path mismatch; no automatic migration')
    else:
        # Compose creates bind directories before starting dependencies. Accept
        # only its empty, root-owned directory skeleton, never old data/links.
        pending = list(root.iterdir())
        while pending:
            item = pending.pop()
            info = item.lstat()
            relative = str(item.relative_to(root))
            if relative in ('.env', 'compose.yaml') and stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                continue
            if (relative not in DIRECTORIES or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o755):
                raise ValueError('existing data or unsafe unmarked directory: ' + relative)
            # Descend only into verified skeleton directories, never links or
            # unrelated app data. Finish preflight before any ownership change.
            pending.extend(item.iterdir())
        os.chown(root, 0, 0)
        os.chmod(root, 0o755)
        json_file(marker, {'schema': 1, 'host_root': host_root})
    if root.stat().st_uid != 0 or root.stat().st_mode & 0o022:
        raise ValueError('installation root must be administrator-owned and not group/world writable')
    for name, (uid, gid, mode) in DIRECTORIES.items():
        path = root / name
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            info = path.lstat()
            if (stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o755 and not any(path.iterdir())):
                path.chmod(mode)
                os.chown(path, uid, gid)
                info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                    or stat.S_IMODE(info.st_mode) != mode):
                raise ValueError('unsafe installation directory: ' + name)
        else:
            path.chmod(mode)
            os.chown(path, uid, gid)
    for name, gid in [('management', 30002), ('approval-service', 30004), ('verification-service', 30005)]:
        path = root / 'config/service-keys' / name / 'key'
        create_file(path, secrets.token_hex(32) + '\n', 0o640, gid)
        if len(path.read_text().strip()) != 64:
            raise ValueError('invalid existing service key')
    path = root / 'config/agent-keys/openclaw.key'
    create_file(path, secrets.token_hex(32) + '\n', 0o640, 30002)
    if len(path.read_text().strip()) != 64:
        raise ValueError('invalid existing agent key')
    json_file(root / 'config/management/gateway.json', {
        'projects': {}, 'secret_file': '/etc/compose-cd/service-keys/management/key',
        'nonce_db': '/var/lib/compose-cd-management/nonces.sqlite',
        'agents': {'openclaw': '/etc/compose-cd/agent-keys/openclaw.key'}})
    policy = json.loads(Path(__file__).with_name('provisioning-default.json').read_text())
    policy['authorization']['service_key'] = '/etc/compose-cd/service-keys/approval-service/key'
    policy['verification']['service_key'] = '/etc/compose-cd/service-keys/verification-service/key'
    policy['workspace'] = host_root + '/state/workspace'
    policy['storage']['config']['path'] = host_root + '/apps/config'
    policy['storage']['downloads']['path'] = host_root + '/apps/downloads'
    json_file(root / 'config/provisioning/policy.json', policy)
    serve = {'TCP': {}, 'Web': {}, 'AllowFunnel': {}}
    for port, backend in [(443, 18793), (8443, 18792)]:
        host = '${TS_CERT_DOMAIN}:' + str(port)
        serve['TCP'][str(port)] = {'HTTPS': True}
        serve['Web'][host] = {'Handlers': {'/': {'Proxy': f'http://127.0.0.1:{backend}'}}}
        serve['AllowFunnel'][host] = False
    json_file(root / 'config/tailscale/serve.json', serve)
    print('Initialization complete. Existing keys, policies, identities and app data preserved.', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='/install')
    parser.add_argument('--host-root', default=os.environ.get('DEPLOY_ROOT'))
    args = parser.parse_args()
    # Existing pre-parameterization Compose files can keep using their recorded
    # installation root on an edge-image upgrade. Never guess for fresh installs.
    if args.host_root is None:
        marker = Path(args.root) / 'installation.json'
        if marker.exists() or marker.is_symlink():
            check_regular(marker, 0o644, 0)
            args.host_root = json.loads(marker.read_text()).get('host_root')
    initialize(args.root, args.host_root)


if __name__ == '__main__':
    main()
