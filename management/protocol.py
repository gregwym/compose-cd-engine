"""Bounded, data-only management protocol. No caller-supplied Docker arguments."""
import hashlib
import hmac
import json
import re
import sqlite3
import time
from pathlib import Path

MAX_REQUEST = 2048
MAX_RESPONSE = 65536
ACTIONS = frozenset({'status', 'logs', 'start', 'stop', 'restart', 'diagnose', 'update'})
ID = re.compile(r'[a-z0-9][a-z0-9-]{0,47}')


def request(raw):
    if len(raw) > MAX_REQUEST:
        raise ValueError('request too large')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'project', 'action', 'request_id', 'timestamp'}:
        raise ValueError('invalid request fields')
    if (not isinstance(value['project'], str) or not ID.fullmatch(value['project'])
            or not isinstance(value['action'], str) or value['action'] not in ACTIONS
            or not isinstance(value['request_id'], str)
            or not re.fullmatch('[a-f0-9]{32}', value['request_id'])
            or type(value['timestamp']) is not int):
        raise ValueError('invalid request')
    return value


def authenticate(raw, signature, secret, database, now=None, validator=request, limit=MAX_REQUEST):
    # The signature binds exact body bytes including action/project/time/nonce.
    if len(secret) < 32 or len(raw) > limit:
        raise ValueError('invalid authentication input')
    expected = 'sha256=' + hmac.new(secret, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError('authentication failed')
    value = validator(raw)
    now = int(time.time()) if now is None else now
    if abs(now - value['timestamp']) > 60:
        raise ValueError('expired request')
    reserve_nonce(value, database, now)
    return value


def reserve_nonce(value, database, now=None):
    now = int(time.time()) if now is None else now
    # Durable UNIQUE reservation before dispatch: at-most-once even on restart.
    with sqlite3.connect(database, timeout=2) as db:
        db.execute('CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)')
        db.execute('DELETE FROM nonces WHERE expires < ?', (now,))
        if db.execute('SELECT count(*) FROM nonces').fetchone()[0] >= 10000:
            raise ValueError('replay store full')
        try:
            db.execute('INSERT INTO nonces VALUES (?, ?)', (value['request_id'], value['timestamp'] + 121))
        except sqlite3.IntegrityError:
            raise ValueError('replayed request') from None


def protected_file(path):
    path = Path(path)
    # Check ancestors too: a safe file in a writable directory is replaceable.
    for item in [path, *path.parents]:
        st = item.lstat()
        if item.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('unsafe administrator policy path')
    if not path.is_file():
        raise ValueError('policy must be a regular file')
    return path


def trusted_json(path):
    return json.loads(protected_file(path).read_text())


def read_frame(connection, limit):
    data = bytearray()
    while True:
        part = connection.recv(min(4096, limit + 1 - len(data)))
        if not part:
            raise ValueError('truncated frame')
        data.extend(part)
        if len(data) > limit:
            raise ValueError('oversized frame')
        if b'\n' in part:
            if not data.endswith(b'\n') or data.count(b'\n') != 1:
                raise ValueError('invalid frame')
            return bytes(data[:-1])
