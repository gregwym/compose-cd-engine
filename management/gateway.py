"""Unprivileged private-network API; no Docker socket, policy writes or shell."""
import json
import os
import socket
import sqlite3
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from receiver.receiver import BoundedHTTPServer
from management.protocol import MAX_REQUEST, MAX_RESPONSE, ID, ACTIONS, authenticate, trusted_json, protected_file, read_frame


def load(path):
    cfg = trusted_json(path)
    if not isinstance(cfg, dict) or set(cfg) != {'projects', 'secret_file', 'nonce_db'}:
        raise ValueError('invalid gateway policy')
    if not isinstance(cfg['projects'], dict) or not cfg['projects']:
        raise ValueError('no approved projects')
    for project, policy in cfg['projects'].items():
        if (not ID.fullmatch(project) or set(policy) != {'socket', 'actions'}
                or not isinstance(policy['socket'], str)
                or not policy['socket'].startswith('/run/compose-cd-management/')
                or '..' in Path(policy['socket']).parts
                or not isinstance(policy['actions'], list) or not policy['actions']
                or not set(policy['actions']) <= ACTIONS):
            raise ValueError('invalid gateway project')
    secret_path = protected_file(cfg['secret_file'])
    st = secret_path.lstat()
    if (secret_path.is_symlink() or not secret_path.is_file() or st.st_uid != 0
            or st.st_mode & 0o027):
        raise ValueError('unsafe gateway secret')
    secret = secret_path.read_bytes().strip()
    if len(secret) < 32:
        raise ValueError('short gateway secret')
    # Keep this DB on persistent gateway-only storage, never a shared inbox.
    if not Path(cfg['nonce_db']).is_absolute():
        raise ValueError('nonce database must be absolute')
    return cfg, secret


class Gateway(BaseHTTPRequestHandler):
    cfg = None
    secret = None

    def log_message(self, *_args):
        pass

    def respond(self, code, result):
        data = json.dumps(result, separators=(',', ':')).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != '/v1/manage':
            self.respond(404, {'status': 'not_found'})
            return
        try:
            if (len(self.headers.get_all('Content-Length', [])) != 1
                    or len(self.headers.get_all('X-Management-Signature', [])) != 1
                    or self.headers.get('Transfer-Encoding')):
                raise ValueError('ambiguous framing')
            length = int(self.headers['Content-Length'])
            if not 0 < length <= MAX_REQUEST:
                raise ValueError('invalid size')
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('truncated body')
            value = authenticate(raw, self.headers['X-Management-Signature'], self.secret, self.cfg['nonce_db'])
            policy = self.cfg['projects'].get(value['project'])
            if policy is None or value['action'] not in policy['actions']:
                raise ValueError('not authorized')
        except (ValueError, TypeError, KeyError, UnicodeError):
            self.respond(403, {'status': 'denied'})
            return
        except (OSError, sqlite3.Error):
            self.respond(503, {'status': 'unavailable'})
            return
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(10)
                connection.connect(policy['socket'])
                connection.sendall(json.dumps(value).encode() + b'\n')
                result = json.loads(read_frame(connection, MAX_RESPONSE))
            self.respond(200, result)
        except (OSError, ValueError):
            # Do not leak Docker stderr or host paths. Operation may still finish.
            self.respond(503, {'status': 'outcome_unknown', 'request_id': value['request_id']})


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', default='/etc/compose-cd/management/gateway.json')
    args = parser.parse_args()
    Gateway.cfg, Gateway.secret = load(args.policy)
    os.umask(0o077)
    BoundedHTTPServer(('0.0.0.0', 18792), Gateway).serve_forever()


if __name__ == '__main__':
    main()
