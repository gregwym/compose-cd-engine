"""Private approval origin. No Docker socket, agent credentials or app data."""
import argparse
import hashlib
import json
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit
from authorization import rpc
from authorization.passkeys import Passkeys
from authorization.scope import require
from authorization.store import Store
from deployer import schema
from management.protocol import trusted_json
from receiver.receiver import BoundedHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send(self, code, data, kind='application/json', cookie=None):
        raw = schema.canonical(data).encode() if kind == 'application/json' else data
        self.send_response(code)
        for key, value in {'Content-Type': kind, 'Content-Length': str(len(raw)), 'Cache-Control': 'no-store',
                           'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                           'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                           'Permissions-Policy': 'publickey-credentials-get=(self), publickey-credentials-create=(self)',
                           'Strict-Transport-Security': 'max-age=31536000'}.items():
            self.send_header(key, value)
        if cookie:
            self.send_header('Set-Cookie', '__Host-cd=' + cookie + '; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=600')
        self.end_headers()
        self.wfile.write(raw)

    def session(self, create=False):
        cookie = SimpleCookie(self.headers.get('Cookie', ''))
        token = cookie['__Host-cd'].value if '__Host-cd' in cookie else ''
        sid = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with self.server.session_lock:
            self.server.sessions = {k: v for k, v in self.server.sessions.items() if v['expires'] > now}
            row = self.server.sessions.get(sid)
            if row:
                return sid, row, None
            require(create and len(self.server.sessions) < 100)
            token = secrets.token_urlsafe(32)
            sid = hashlib.sha256(token.encode()).hexdigest()
            row = {'csrf': secrets.token_urlsafe(32), 'expires': now + 600, 'admin': None}
            self.server.sessions[sid] = row
            return sid, row, token

    def host(self):
        require(self.headers.get('Host') == urlsplit(self.server.origin).netloc)

    def do_GET(self):
        try:
            self.host()
            if self.path == '/healthz':
                return self.send(200, {'status': 'ready'})
            if self.path in ('/static/app.js', '/static/style.css'):
                kind = 'application/javascript' if self.path.endswith('.js') else 'text/css'
                return self.send(200, Path(__file__).with_name(self.path.split('/')[-1]).read_bytes(), kind)
            if self.path == '/api/session':
                _, row, token = self.session(create=True)
                return self.send(200, {'csrf': row['csrf'], 'authenticated': bool(row['admin'])}, cookie=token)
            if self.path == '/api/data':
                _, session, _ = self.session()
                require(session['admin'])
                with self.server.store.db() as db:
                    requests = [self.server.store.public_request(r) for r in db.execute('SELECT * FROM requests ORDER BY rowid DESC LIMIT 100')]
                    grants = [{k: r[k] for k in ('id', 'project', 'agent', 'admin', 'mode', 'created', 'expires', 'revision', 'status')}
                              | {'scope': json.loads(r['scope'])} for r in db.execute('SELECT * FROM grants ORDER BY rowid DESC LIMIT 100')]
                    credentials = [{'id': bytes(r['id']).hex()} for r in db.execute('SELECT id FROM credentials WHERE admin=? AND active=1', (session['admin'],))]
                    events = [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY seq DESC LIMIT 100')]
                for request in requests:
                    request['grant_diff'] = self.server.store.check({'agent': request['agent'], 'project': request['project'],
                        'plan': request['plan_id'], 'policy': request['policy'], 'scope': request['scope']})['grant_diff']
                return self.send(200, {'requests': requests, 'grants': grants, 'credentials': credentials, 'audit': events})
            require(self.path in ('/', '/enroll') or (self.path.startswith('/requests/') and schema.HEX.fullmatch(self.path[10:])))
            self.send(200, Path(__file__).with_name('index.html').read_bytes(), 'text/html; charset=utf-8')
        except Exception:
            self.send(403, {'status': 'denied'})

    def do_POST(self):
        try:
            self.host()
            require(self.headers.get('Origin') == self.server.origin)
            require(self.headers.get('Content-Type') == 'application/json' and not self.headers.get('Transfer-Encoding')
                    and len(self.headers.get_all('Content-Length', [])) == 1)
            length = int(self.headers['Content-Length'])
            require(0 < length <= 32768)
            self.connection.settimeout(5)
            sid, session, _ = self.session()
            require(secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']))
            value = json.loads(self.rfile.read(length))
            if self.path == '/api/begin':
                schema.fields(value, {'action'}, {'target', 'token'})
                result = self.server.passkeys.begin(sid, value['action'], value.get('target', ''), value.get('token'), session['admin'])
            elif self.path == '/api/finish':
                schema.fields(value, {'ceremony_id', 'response'})
                result = self.server.passkeys.finish(sid, value['ceremony_id'], value['response'], session['admin'])
                if result.get('admin'):
                    session['admin'] = result['admin']
            elif self.path == '/api/logout':
                session['admin'] = None
                result = {'status': 'success'}
            else:
                require(False)
            self.send(200, result)
        except Exception:
            self.send(403, {'status': 'denied'})


def load(path):
    cfg = trusted_json(path)
    schema.fields(cfg, {'state', 'origin', 'rp_id', 'socket', 'service_key'})
    origin = urlsplit(cfg['origin'])
    require(origin.scheme == 'https' and origin.hostname == cfg['rp_id'] and origin.path == ''
            and not origin.username and not origin.password and not origin.query and not origin.fragment)
    from deployer.service import protected_directory
    root = Path(cfg['state'])
    # Approval process owns its leaf; its parents must remain administrator-owned.
    protected_directory(root.parent)
    require(not root.is_symlink() and root.is_dir() and not root.stat().st_mode & 0o077
            and root.stat().st_uid == os.geteuid())
    return cfg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', default='/etc/compose-cd/approval/policy.json')
    parser.add_argument('--bootstrap', metavar='ADMIN', help='local trusted administrator console only; one-time 10 minute token')
    parser.add_argument('--listen', default='0.0.0.0', choices=['0.0.0.0', '127.0.0.1'])
    parser.add_argument('--wait-policy', action='store_true', help='wait for first-install domain discovery')
    parser.add_argument('--first-enrollment-console', action='store_true', help='print first-owner enrollment codes to trusted container logs until enrolled')
    args = parser.parse_args()
    os.umask(0o077)
    if args.wait_policy:
        print('Waiting for Tailscale login and HTTPS domain configuration.', flush=True)
        while not Path(args.policy).exists():
            time.sleep(2)
    cfg = load(args.policy)
    store = Store(Path(cfg['state']) / 'authorization.sqlite', cfg['origin'])
    if args.bootstrap:
        print(store.bootstrap(args.bootstrap))
        return
    server = BoundedHTTPServer((args.listen, 18793), Handler)
    server.store, server.origin = store, cfg['origin']
    server.passkeys = Passkeys(store, cfg['rp_id'], cfg['origin'])
    server.sessions, server.session_lock = {}, threading.Lock()
    threading.Thread(target=rpc.serve, args=(cfg, store.rpc, str(Path(cfg['state']) / 'nonces.sqlite')), daemon=True).start()
    if args.first_enrollment_console:
        from installer.enrollment import console
        threading.Thread(target=console, args=(store,), daemon=True).start()
    server.serve_forever()


if __name__ == '__main__':
    main()
