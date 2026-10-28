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
ASSIGN = re.compile(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')


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


def write_all(fd, data):
    """os.write may write less than asked without raising; anything short of all of it is an error."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError('short write')
        view = view[written:]


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
        write_all(fd, data)
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
        write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    old = sorted(p for p in path.parent.glob(path.name + '.bak-*') if p.is_file() and not p.is_symlink())
    for item in old[:-KEEP_BACKUPS]:
        item.unlink()
    return target.name


def closed(rest, quote):
    if quote == "'":
        return "'" in rest
    escaped = False
    for char in rest:
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '"':
            return True
    return False


def entries(text):
    """Logical .env entries as (key or None, text). Quoted values may span lines, as Compose allows,
    so assignment-looking lines inside them belong to the value."""
    lines, out, i = text.splitlines(), [], 0
    while i < len(lines):
        match = ASSIGN.match(lines[i])
        end = i
        if match and match.group(2)[:1] in ('"', "'"):
            quote, rest = match.group(2)[0], match.group(2)[1:]
            while not closed(rest, quote) and end + 1 < len(lines):
                end += 1
                rest += '\n' + lines[end]
        out.append((match.group(1) if match else None, '\n'.join(lines[i:end + 1])))
        i = end + 1
    return out


def env_values(data):
    """The values in .env text, unquoted, for scrubbing them from Compose error output."""
    values = set()
    for key, text in entries((data or b'').decode('utf-8', 'replace')):
        if key:
            value = text.split('=', 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            values.add(value)
    return values


def env_keys(data):
    keys = []
    for key, _ in entries((data or b'').decode('utf-8', 'replace')):
        if key and key not in keys:
            keys.append(key)
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
    out, done = [], set()
    for key, line in entries((data or b'').decode('utf-8')):
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
        return {key: text for key, text in entries((data or b'').decode('utf-8', 'replace')) if key}
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
