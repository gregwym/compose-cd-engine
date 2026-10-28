"""In-place edits of Container Manager project files: compose.yaml and .env."""
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from shared.wire import Denied

MAX_FILE = 256 * 1024
KEEP_BACKUPS = 5
KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
PLAIN = re.compile(r'[A-Za-z0-9_./:@+,=%-]*')


def read(path):
    """Return file bytes, or None when absent. Never follows a final symlink."""
    path = Path(path)
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise Denied('unsafe_file', path.name)
    data = path.read_bytes()
    if len(data) > MAX_FILE:
        raise Denied('file_too_large', path.name)
    return data


def write_in_place(path, data, like=None, mode=0o600):
    """Overwrite an existing file without replacing its inode, so the owner,
    mode and Synology ACL stay. A new file copies ownership from `like`."""
    path = Path(path)
    if os.path.lexists(path):
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        os.fchmod(fd, mode)
        if like is not None:
            info = os.stat(like)
            os.fchown(fd, info.st_uid, info.st_gid)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def remove(path):
    path = Path(path)
    if os.path.lexists(path):
        path.unlink()


def backup(path, data):
    """Keep a visible copy next to the original, e.g. compose.yaml.bak-20261028T101500.123456Z.
    Fixed-width names sort oldest first."""
    if data is None:
        return None
    path = Path(path)
    while True:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        target = path.with_name(f'{path.name}.bak-{stamp}')
        if not os.path.lexists(target):
            break
    info = path.stat()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, info.st_mode & 0o777)
        os.fchown(fd, info.st_uid, info.st_gid)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    old = sorted(p for p in path.parent.glob(path.name + '.bak-*') if p.is_file() and not p.is_symlink())
    for item in old[:-KEEP_BACKUPS]:
        item.unlink()
    return target.name


def env_keys(data):
    keys = []
    for line in (data or b'').decode('utf-8', 'replace').splitlines():
        match = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', line)
        if match and match.group(1) not in keys:
            keys.append(match.group(1))
    return keys


def env_value(value):
    if not isinstance(value, str) or '\n' in value or '\r' in value or '\0' in value or len(value) > 4096:
        raise Denied('invalid_env_value')
    if PLAIN.fullmatch(value):
        return value
    if "'" in value:
        raise Denied('invalid_env_value', 'single quotes are not supported')
    return "'" + value + "'"


def edit_env(data, set_values=None, unset=()):
    """Apply set/unset to .env text, keeping comments, order and other lines."""
    set_values = dict(set_values or {})
    unset = list(unset or ())
    for key in [*set_values, *unset]:
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise Denied('invalid_env_key', key if isinstance(key, str) else None)
    if set(set_values) & set(unset):
        raise Denied('invalid_env_change', 'key both set and unset')
    lines = (data or b'').decode('utf-8').splitlines()
    out, done = [], set()
    for line in lines:
        match = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', line)
        key = match.group(1) if match else None
        if key in unset:
            continue
        if key in set_values:
            if key in done:
                continue
            line = f'{key}={env_value(set_values[key])}'
            done.add(key)
        out.append(line)
    for key, value in set_values.items():
        if key not in done:
            out.append(f'{key}={env_value(value)}')
    return ('\n'.join(out) + '\n').encode() if out else b''


def env_summary(before, after):
    def parse(data):
        values = {}
        for line in (data or b'').decode('utf-8', 'replace').splitlines():
            match = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$', line)
            if match:
                values[match.group(1)] = match.group(2)
        return values
    old, new = parse(before), parse(after)
    return {'added': sorted(set(new) - set(old)), 'removed': sorted(set(old) - set(new)),
            'changed': sorted(k for k in set(old) & set(new) if old[k] != new[k])}


VARIABLE = re.compile(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::?-[^}]*)?\}?')


def image_edit(compose, raw_image, new_image):
    """Point one service at a new image. Returns (compose, env_set).

    `raw_image` is the service's uninterpolated `image:` value. A pure variable
    reference is updated in .env; a literal is replaced on its only line."""
    whole = VARIABLE.fullmatch(raw_image)
    if whole:
        return compose, {whole.group(1): new_image}
    text = compose.decode('utf-8')
    pattern = re.compile(r'^(\s*image:\s*)(["\']?)' + re.escape(raw_image) + r'\2(\s*(?:#.*)?)$', re.M)
    if len(pattern.findall(text)) != 1:
        raise Denied('image_line_not_found', 'expected exactly one matching image: line')
    return pattern.sub(lambda m: m.group(1) + m.group(2) + new_image + m.group(2) + m.group(3), text).encode(), {}
