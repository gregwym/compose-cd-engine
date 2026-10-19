"""Disposable CI adapter: real HTTP/HMAC/Unix RPC and software Passkey signing.

Not an installation tool; never bootstrap production credentials from an agent.
The test fixture is mounted only in CI. Image substitution remains explicitly
local-only in smoke_projects; real registry verification is a separate test.
"""
import http.client
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from authorization import rpc
from authorization.protocol import ROUTES
from deployer import schema
from management.gateway import Gateway
from receiver.receiver import BoundedHTTPServer


class Adapter:
    def __init__(self, root, cfg, project):
        assert os.environ.get('CD_DISPOSABLE_CI') == '1'
        sys.path.insert(0, '/integration/tests')
        from test_authorization_http import BrowserApprovalFlow
        self.browser = BrowserApprovalFlow('test_real_browser_protocol_enroll_login_approve_list_and_revoke')
        self.browser.setUp()
        _, session = self.browser.call('/api/session')
        self.browser.csrf = session['csrf']
        self.browser.ceremony('enroll', token=self.browser.server.store.bootstrap('owner'))
        self.browser.ceremony('login')
        self.project, self.root = project, root
        self.key = os.urandom(48).hex().encode()
        key = root / 'agent.key'; key.write_bytes(self.key); key.chmod(0o600)
        service_key = root / 'service.key'; service_key.write_bytes(os.urandom(48).hex().encode()); service_key.chmod(0o600)
        (root / 'control').mkdir(mode=0o700)
        cfg['authorization'] = {'socket': str(root / 'auth.sock'), 'service_key': str(service_key), 'agents': {'openclaw': str(key)}}
        cfg['operations'] += ['grant_request', 'grant_status', 'grants', 'projects', 'diagnose', 'retire']
        self.cfg = cfg
        self.rpc_thread = threading.Thread(target=rpc.serve,
            args=(cfg['authorization'], self.browser.server.store.rpc, str(root / 'rpc-nonces.sqlite')), daemon=True)
        self.rpc_thread.start()
        self.wait(root / 'auth.sock')

    @staticmethod
    def wait(path):
        for _ in range(100):
            if path.exists():
                return
            time.sleep(.05)
        raise AssertionError('test socket did not start')

    def bind(self, service):
        import deployer.service as module
        module.SOCKET = str(self.root / 'control' / 'projects.sock')
        threading.Thread(target=service.serve, daemon=True).start()
        self.wait(Path(module.SOCKET))
        class TestGateway(Gateway):
            cfg = {'projects': {}, 'agents': self.cfg['authorization']['agents'], 'nonce_db': str(self.root / 'http-nonces.sqlite')}
            secret = b'unused-legacy-secret-only-for-test' * 2
        self.server = BoundedHTTPServer(('127.0.0.1', 0), TestGateway)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def call(self, op, payload=None):
        value = {'version': 2, 'agent': 'openclaw', 'project': self.project, 'operation': op,
                 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time()), 'payload': payload or {}}
        raw = schema.canonical(value).encode()
        route = next(path for path, operation in ROUTES.items() if operation == op)
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=15)
        client.request('POST', route, raw, {'X-Management-Signature': rpc.signature(raw, self.key)})
        response = client.getresponse()
        assert response.status == 200, response.status
        result = json.loads(response.read()); client.close()
        return result

    def approve(self, plan_id):
        assert self.call('apply', {'plan_id': plan_id})['status'] == 'not_authorized'
        request = self.call('grant_request', {'plan_id': plan_id, 'mode': 'persistent', 'lifetime': 3600})
        assert self.call('grant_status', {'approval_id': request['request_id']})['status'] == 'pending'
        self.browser.ceremony('approve', request['request_id'])
        assert self.call('grant_status', {'approval_id': request['request_id']})['status'] == 'approved'

    def finish(self, task):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = self.call('task', {'task_id': task})['status']
            if result not in ('queued', 'running'):
                return result
            time.sleep(.2)
        raise AssertionError('disposable authorization task timed out')

    def close(self):
        self.server.shutdown(); self.server.server_close()
        self.browser.tearDown()
