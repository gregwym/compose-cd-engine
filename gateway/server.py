"""Gateway entry point: owner page, agent API and webhooks, behind Tailscale Serve."""
import hashlib
import json
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from gateway import agents, tailscale
from gateway.core import Gateway
from gateway.passkeys import Passkeys
from gateway.store import Store
from shared.wire import Denied, canonical

STATIC = Path(__file__).with_name('static')
PAGES = ('/', '/enroll')
PREFIXES = ('/r/', '/p/')
SESSION_TTL = 900
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, gateway, passkeys):
        super().__init__(address, handler)
        self.gateway, self.passkeys = gateway, passkeys
        self.sessions, self.lock = {}, threading.Lock()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(30)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    server_version = 'compose-deployer'

    def log_message(self, *_args):
        pass  # never log request bodies or headers

    def reply(self, code, data, kind='application/json', cookie=None):
        raw = canonical(data).encode() if kind == 'application/json' else data
        self.send_response(code)
        headers = {'Content-Type': kind, 'Content-Length': str(len(raw)), 'Cache-Control': 'no-store',
                   'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                   'Content-Security-Policy': CSP, 'Strict-Transport-Security': 'max-age=31536000'}
        for key, value in headers.items():
            self.send_header(key, value)
        if cookie:
            self.send_header('Set-Cookie', f'__Host-cd={cookie}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}')
        self.end_headers()
        self.wfile.write(raw)

    def fail(self, exc):
        if isinstance(exc, Denied):
            return self.reply(403, {'ok': False, 'error': exc.code, 'detail': exc.detail})
        return self.reply(400, {'ok': False, 'error': 'bad_request'})

    def body(self, limit):
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            raise Denied('bad_request')
        length = int(self.headers['Content-Length'])
        if not 0 < length <= limit or self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise Denied('bad_request')
        data = self.rfile.read(length)
        if len(data) != length:
            raise Denied('bad_request')
        return data


class OwnerHandler(Handler):
    def session(self, create=False):
        cookie = SimpleCookie(self.headers.get('Cookie', ''))
        token = cookie['__Host-cd'].value if '__Host-cd' in cookie else ''
        key = hashlib.sha256(token.encode()).hexdigest()
        stamp = time.time()
        with self.server.lock:
            self.server.sessions = {k: v for k, v in self.server.sessions.items() if v['expires'] > stamp}
            if token and key in self.server.sessions:
                return key, self.server.sessions[key], None
            if not create or len(self.server.sessions) >= 200:
                raise Denied('no_session')
            token = secrets.token_urlsafe(32)
            key = hashlib.sha256(token.encode()).hexdigest()
            self.server.sessions[key] = {'csrf': secrets.token_urlsafe(24), 'owner': False, 'expires': stamp + SESSION_TTL}
            return key, self.server.sessions[key], token

    def signed_in(self):
        try:
            return self.session()[1]['owner']
        except Denied:
            return False

    def check_host(self):
        host = self.server.gateway.host
        if host not in (self.headers.get('Host'), self.headers.get('X-Forwarded-Host')):
            raise Denied('wrong_host')

    def do_GET(self):
        try:
            gateway, path = self.server.gateway, self.path.split('?', 1)[0]
            if path == '/healthz':
                return self.reply(200, {'status': 'ready'})
            self.check_host()
            if path.startswith('/static/') and path[8:] in ('app.js', 'style.css'):
                kind = 'text/javascript' if path.endswith('.js') else 'text/css'
                return self.reply(200, (STATIC / path[8:]).read_bytes(), kind)
            if path in PAGES or (path.startswith(PREFIXES) and 10 <= len(path) <= 64):
                return self.reply(200, (STATIC / 'index.html').read_bytes(), 'text/html; charset=utf-8')
            if path == '/api/session':
                _, session, token = self.session(create=True)
                return self.reply(200, {'csrf': session['csrf'], 'owner': session['owner'],
                                        'enrolled': gateway.store.enrolled()}, cookie=token)
            if path.startswith('/api/request/'):
                item = gateway.store.request(path[13:])
                if not item:
                    raise Denied('not_found')
                # Agents know their request ids, so file content and risks need a signed-in owner.
                return self.reply(200, gateway.public(item, owner=self.signed_in()))
            if path.startswith('/api/pairing/'):
                with gateway.store.db() as db:
                    row = db.execute('SELECT * FROM agents WHERE token=?', (path[13:],)).fetchone()
                if not row:
                    raise Denied('not_found')
                status = 'expired' if row['status'] == 'pending' and row['expires'] <= time.time() else row['status']
                return self.reply(200, {'agent': row['id'], 'label': row['label'], 'status': status,
                                        'fingerprint': agents.fingerprint(row['public_key'])})
            _, session, _ = self.session()
            if not session['owner']:
                raise Denied('sign_in_required')
            if path == '/api/dashboard':
                return self.reply(200, gateway.store.dashboard())
            if path.startswith('/api/trigger/'):
                with gateway.store.db() as db:
                    row = db.execute('SELECT id, secret FROM triggers WHERE id=?', (path[13:],)).fetchone()
                if not row:
                    raise Denied('not_found')
                return self.reply(200, {'url': f'https://{gateway.host}:8443/hooks/{row["id"]}', 'secret': row['secret']})
            raise Denied('not_found')
        except Exception as exc:
            self.fail(exc)

    def do_POST(self):
        try:
            gateway, path = self.server.gateway, self.path
            self.check_host()
            if path == '/agent':
                return self.agent()
            if self.headers.get('Origin') != gateway.origin:
                raise Denied('wrong_origin')
            sid, session, _ = self.session()
            if not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                raise Denied('csrf')
            value = json.loads(self.body(65536))
            if path == '/api/begin':
                result = self.server.passkeys.begin(sid, value.get('action'), str(value.get('target', '')),
                                                    value.get('token'), session['owner'])
            elif path == '/api/finish':
                result = self.server.passkeys.finish(sid, value.get('ceremony_id'), value.get('response'))
                if result['action'] in ('login', 'enroll'):
                    session['owner'] = True
                elif result['action'] == 'approve':
                    gateway.execute(result['target'])
                elif result['action'] in ('remove_route', 'remove_trigger'):
                    gateway.sync_serve()
            elif path == '/api/logout':
                session['owner'], result = False, {'status': 'signed_out'}
            else:
                raise Denied('not_found')
            self.reply(200, result)
        except Exception as exc:
            self.fail(exc)

    def agent(self):
        if self.headers.get('Origin') or self.headers.get('Cookie'):
            raise Denied('bad_request')
        raw = self.body(1024 * 1024)
        value = agents.verify(raw, self.headers.get('X-Agent-Signature'), self.server.gateway.host)
        self.server.gateway.store.nonce(value['request_id'])
        self.reply(200, {'ok': True, 'result': self.server.gateway.agent(value)})


class HookHandler(Handler):
    def do_POST(self):
        try:
            if not self.path.startswith('/hooks/'):
                raise Denied('not_found')
            body = self.body(512 * 1024)
            woke = self.server.gateway.webhook(self.path[7:], body, self.headers.get('X-Hub-Signature-256'),
                                               self.headers.get('X-GitHub-Event'))
            self.reply(202 if woke else 200, {'ok': True})
        except Exception as exc:
            self.fail(exc)


def wait_for_domain(path):
    previous = None
    while True:
        try:
            host = tailscale.domain(path)
            message = None if host else 'Waiting for Tailscale login: open the link in the tailscale container log.'
        except (OSError, ValueError) as exc:
            host, message = None, 'Waiting for Tailscale: ' + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        if host:
            return host
        if message != previous:
            print(message, flush=True)
            previous = message
        time.sleep(5)


def enrollment_console(store, origin):
    while not store.enrolled():
        code = store.enrollment_code()
        if code:
            print(f'FIRST PASSKEY: open {origin}/enroll on your iPhone and enter code {code} (valid 10 minutes)', flush=True)
        for _ in range(120):
            if store.enrolled():
                break
            time.sleep(5)
    print('Passkey registered. Owner page: ' + origin + '/', flush=True)


def main():
    state = Path(os.environ.get('CD_STATE', '/var/lib/compose-cd/gateway'))
    socket_path = os.environ.get('CD_TAILSCALE_SOCKET', tailscale.SOCKET)
    os.umask(0o077)
    store = Store(state / 'gateway.sqlite')
    host = wait_for_domain(socket_path)
    if store.meta('domain', host) != host:
        raise SystemExit('Tailscale name changed from ' + store.meta('domain') + '; Passkeys are bound to the old name.')
    origin = 'https://' + host
    gateway = Gateway(store, os.environ.get('CD_RUNNER_SOCKET', '/run/compose-cd/runner.sock'), origin, host,
                      funnel=os.environ.get('CD_FUNNEL') == '1',
                      apply_serve=lambda config: tailscale.apply_serve(config, socket_path))
    while gateway.sync_serve() == 'failed':
        time.sleep(5)
    passkeys = Passkeys(store, host, origin)
    hooks = Server(('127.0.0.1', tailscale.HOOK_PORT), HookHandler, gateway, passkeys)
    owner = Server(('127.0.0.1', tailscale.UI_PORT), OwnerHandler, gateway, passkeys)
    for target in (hooks.serve_forever, gateway.trigger_loop, lambda: enrollment_console(store, origin)):
        threading.Thread(target=target, daemon=True).start()
    print('Gateway ready: ' + origin + '/', flush=True)
    owner.serve_forever()


if __name__ == '__main__':
    main()
