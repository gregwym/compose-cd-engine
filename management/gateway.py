"""Unprivileged private-network API; no Docker socket, policy writes or shell."""
import json
import os
import socket
import sqlite3
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from receiver.receiver import BoundedHTTPServer
from management.protocol import MAX_REQUEST, MAX_RESPONSE, ID, ACTIONS, authenticate, trusted_json, protected_file, read_frame, request


def load(path):
    cfg = trusted_json(path)
    if (not isinstance(cfg, dict) or not {'projects', 'secret_file', 'nonce_db'} <= set(cfg)
            or set(cfg) - {'projects', 'secret_file', 'nonce_db', 'deployer', 'agents', 'legacy_compat'}):
        raise ValueError('invalid gateway policy')
    if not isinstance(cfg['projects'], dict) or (not cfg['projects'] and not cfg.get('deployer') and not cfg.get('agents')):
        raise ValueError('no approved projects')
    for project, policy in cfg['projects'].items():
        if (not ID.fullmatch(project) or set(policy) != {'socket', 'actions'}
                or not isinstance(policy['socket'], str)
                or not policy['socket'].startswith('/run/compose-cd-management/')
                or '..' in Path(policy['socket']).parts
                or not isinstance(policy['actions'], list) or not policy['actions']
                or not set(policy['actions']) <= ACTIONS):
            raise ValueError('invalid gateway project')
    if 'deployer' in cfg:
        from deployer.schema import OPS
        policy = cfg['deployer']
        if (not isinstance(policy, dict) or set(policy) != {'operations'}
                or not isinstance(policy['operations'], list) or not policy['operations']
                or not all(isinstance(x, str) and x in OPS for x in policy['operations'])):
            raise ValueError('invalid deployer policy')
    secret_path = protected_file(cfg['secret_file'])
    st = secret_path.lstat()
    if (secret_path.is_symlink() or not secret_path.is_file() or st.st_uid != 0
            or st.st_mode & 0o027):
        raise ValueError('unsafe gateway secret')
    secret = secret_path.read_bytes().strip()
    if len(secret) < 32:
        raise ValueError('short gateway secret')
    if 'agents' in cfg:
        from deployer.schema import name, check
        check(isinstance(cfg['agents'], dict) and 1 <= len(cfg['agents']) <= 32)
        for agent, keypath in cfg['agents'].items():
            name(agent)
            st = protected_file(keypath).stat()
            check(not st.st_mode & 0o027 and len(Path(keypath).read_bytes().strip()) >= 32)
        if cfg['projects'] and cfg.get('legacy_compat') is not True:
            raise ValueError('explicit fixed legacy compatibility required')
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

    def do_GET(self):
        if self.path == '/healthz':
            from deployer.service import SOCKET
            ready = Path(SOCKET).is_socket()
            self.respond(200 if ready else 503, {'status': 'ready' if ready else 'starting'})
        else:
            self.respond(404, {'status': 'not_found'})

    def do_POST(self):
        from authorization.protocol import ROUTES, request as agent_request
        v2 = self.path in ROUTES and 'agents' in self.cfg
        provisioning = self.path == '/v1/projects' and 'deployer' in self.cfg
        if self.path != '/v1/manage' and not provisioning and not v2:
            self.respond(404, {'status': 'not_found'})
            return
        try:
            if (len(self.headers.get_all('Content-Length', [])) != 1
                    or len(self.headers.get_all('X-Management-Signature', [])) != 1
                    or self.headers.get('Transfer-Encoding')):
                raise ValueError('ambiguous framing')
            length = int(self.headers['Content-Length'])
            from deployer import schema
            limit = 60000 if v2 else (schema.MAX_REQUEST if provisioning else MAX_REQUEST)
            if not 0 < length <= limit:
                raise ValueError('invalid size')
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('truncated body')
            secret = self.secret
            if v2:
                parsed = agent_request(raw)
                if parsed['operation'] != ROUTES[self.path] or parsed['agent'] not in self.cfg['agents']:
                    raise ValueError('invalid route or identity')
                secret = protected_file(self.cfg['agents'][parsed['agent']]).read_bytes().strip()
            elif 'agents' in self.cfg and (provisioning or self.cfg.get('legacy_compat') is not True):
                raise ValueError('v2 required')
            value = authenticate(raw, self.headers['X-Management-Signature'], secret, self.cfg['nonce_db'],
                                 validator=agent_request if v2 else (schema.request if provisioning else request),
                                 limit=limit)
            if provisioning or v2:
                if not v2 and value['operation'] not in self.cfg['deployer']['operations']:
                    raise ValueError('not authorized')
                from deployer.service import SOCKET
                socket_path = SOCKET
            else:
                policy = self.cfg['projects'].get(value['project'])
                if policy is None or value['action'] not in policy['actions']:
                    raise ValueError('not authorized')
                socket_path = policy['socket']
        except (ValueError, TypeError, KeyError, UnicodeError):
            self.respond(403, {'status': 'denied'})
            return
        except (OSError, sqlite3.Error):
            self.respond(503, {'status': 'unavailable'})
            return
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(10)
                connection.connect(socket_path)
                wire = {'raw': raw.decode(), 'signature': self.headers['X-Management-Signature']} if v2 else value
                connection.sendall(json.dumps(wire).encode() + b'\n')
                result = json.loads(read_frame(connection, MAX_RESPONSE))
            self.respond(200, result)
        except (OSError, ValueError):
            # Do not leak Docker stderr or host paths. Operation may still finish.
            self.respond(503, {'status': 'outcome_unknown', 'request_id': value['request_id']})


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', default='/etc/compose-cd/management/gateway.json')
    parser.add_argument('--listen', default='0.0.0.0', choices=['0.0.0.0', '127.0.0.1'])
    args = parser.parse_args()
    Gateway.cfg, Gateway.secret = load(args.policy)
    os.umask(0o077)
    BoundedHTTPServer((args.listen, 18792), Gateway).serve_forever()


if __name__ == '__main__':
    main()
