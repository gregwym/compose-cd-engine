"""Private bounded RPC. Service key is separate from every agent credential."""
import hashlib
import hmac
import json
import socket
import time
import uuid
from pathlib import Path
from deployer import schema
from management.protocol import read_frame
from authorization.scope import Denied


def service_key(path):
    from management.protocol import protected_file
    file = protected_file(path)
    schema.check(not file.stat().st_mode & 0o027)
    key = file.read_bytes().strip()
    schema.check(len(key) >= 32)
    return key


def signature(raw, key):
    return 'sha256=' + hmac.new(key, raw, hashlib.sha256).hexdigest()


def call(cfg, operation, payload):
    value = {'operation': operation, 'payload': payload, 'timestamp': int(time.time()), 'request_id': uuid.uuid4().hex}
    raw = schema.canonical(value).encode()
    key = service_key(cfg['service_key'])
    wire = schema.canonical({'value': value, 'signature': signature(raw, key)}).encode()
    schema.check(len(wire) <= 65536)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(240 if operation == 'verify' else 10)
            sock.connect(cfg['socket'])
            sock.sendall(wire + b'\n')
            result = json.loads(read_frame(sock, 65536))
    except (OSError, ValueError):
        raise Denied('authorization_unavailable') from None
    if result.get('error'):
        raise Denied(result['error'] if result['error'] in {
            'not_authorized', 'stale_request', 'rate_limited', 'verification_failed'} else 'authorization_unavailable')
    return result


def serve(cfg, handler, nonce_db):
    from management.protocol import authenticate
    path = Path(cfg['socket'])
    if path.exists():
        schema.check(path.is_socket())
        path.unlink()
    key = service_key(cfg['service_key'])
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        import os
        group = int(os.environ.get('CD_RPC_GID', str(os.getegid())))
        os.chown(path, os.geteuid(), group)
        os.chmod(path, 0o660)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                try:
                    wire = json.loads(read_frame(connection, 65536))
                    schema.fields(wire, {'value', 'signature'})
                    def validate(raw):
                        value = json.loads(raw)
                        schema.fields(value, {'operation', 'payload', 'request_id', 'timestamp'})
                        schema.check(schema.HEX.fullmatch(value['request_id']) and type(value['timestamp']) is int)
                        return value
                    value = authenticate(schema.canonical(wire['value']).encode(), wire['signature'], key,
                                         nonce_db, validator=validate, limit=65536)
                    result = handler(value['operation'], value['payload'])
                except Denied as exc:
                    result = {'error': exc.category}
                except Exception:
                    result = {'error': 'not_authorized'}
                try:
                    raw = schema.canonical(result).encode()
                    schema.check(len(raw) <= 65536)
                    connection.sendall(raw + b'\n')
                except (OSError, ValueError):
                    pass
