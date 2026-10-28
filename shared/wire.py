"""Canonical JSON and the newline-framed gateway <-> runner socket protocol."""
import hashlib
import json
import socket

LIMIT = 4 * 1024 * 1024


class Denied(Exception):
    """An expected refusal. `code` is stable and safe to return to agents."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    data = value if isinstance(value, bytes) else canonical(value).encode()
    return hashlib.sha256(data).hexdigest()


def read_line(sock, limit=LIMIT):
    data = bytearray()
    while not data.endswith(b'\n'):
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise ValueError('frame too large')
    return bytes(data).strip()


def call(path, op, args=None, timeout=1800):
    """Send one request to the runner and return its result or raise Denied."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(canonical({'op': op, 'args': args or {}}).encode() + b'\n')
            reply = json.loads(read_line(sock))
    except (OSError, ValueError) as exc:
        raise Denied('runner_unavailable', type(exc).__name__) from None
    if not reply.get('ok'):
        raise Denied(reply.get('error', 'failed'), reply.get('detail'))
    return reply['result']
