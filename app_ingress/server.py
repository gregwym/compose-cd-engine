"""Serial private socket server. The public frontend never gets privileged secrets."""
import fcntl
import json
import os
import socket
from pathlib import Path
from app_ingress.broker import Broker
from app_ingress.transport import Serve
from authorization import rpc
from authorization.scope import Denied
from deployer.service import protected_directory
from management.protocol import trusted_json, read_frame


def main():
    state = protected_directory('/var/lib/app-ingress')
    protected_directory('/run/app-ingress')
    lock = (state / 'broker.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.umask(0o077)
    database = state / 'broker.sqlite'
    if database.exists():
        from management.protocol import protected_file
        protected_file(database)
    auth = {'socket':'/run/approval/approval.sock','service_key':'/etc/app-ingress-secrets/approval-service.key'}
    broker = Broker(database, lambda: trusted_json('/etc/app-ingress/policy.json'),
                    Serve('/run/tailscale/tailscaled.sock'), lambda op,payload: rpc.call(auth,op,payload))
    path = Path('/run/app-ingress/broker.sock')
    if path.exists():
        if not path.is_socket() or path.is_symlink():
            raise ValueError('unsafe socket path')
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chown(path, 0, 30006)
        os.chmod(path, 0o660)
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(15)
                try:
                    result = broker.wire(json.loads(read_frame(conn, 8192)))
                except Denied as exc:
                    result = {'error':exc.category}
                except Exception:
                    result = {'error':'request_failed'}
                try:
                    conn.sendall(schema_bytes(result) + b'\n')
                except OSError:
                    pass


def schema_bytes(value):
    from deployer import schema
    raw = schema.canonical(value).encode()
    if len(raw) > 65536:
        raise ValueError('oversized response')
    return raw


if __name__ == '__main__':
    main()
