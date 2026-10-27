import http.client
import json
import tempfile
import threading
import unittest
import time
import uuid
from pathlib import Path
from authorization.server import Handler
from authorization.passkeys import Passkeys
from authorization.store import Store
from receiver.receiver import BoundedHTTPServer
from test_authorization import Authenticator, ORIGIN, RP
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authorization import agents
from deployer import schema


class BrowserApprovalFlow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = BoundedHTTPServer(('127.0.0.1', 0), Handler)
        self.server.store = Store(Path(self.temp.name) / 'auth.sqlite', ORIGIN)
        self.server.origin = ORIGIN
        self.server.passkeys = Passkeys(self.server.store, RP, ORIGIN)
        self.server.sessions, self.server.session_lock = {}, threading.Lock()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.cookie = self.csrf = ''
        self.auth = Authenticator()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.temp.cleanup()

    def call(self, path, body=None, extra=None):
        headers = {'Host': RP, 'Origin': ORIGIN, 'Cookie': self.cookie,
                   'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf}
        headers.update(extra or {})
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        client.request('GET' if body is None else 'POST', path, None if body is None else json.dumps(body), headers)
        response = client.getresponse()
        status, data = response.status, response.read()
        cookie = response.getheader('Set-Cookie')
        if cookie:
            self.assertIn('Secure; HttpOnly; SameSite=Strict', cookie)
            self.cookie = cookie.split(';')[0]
        client.close()
        return status, json.loads(data)

    def ceremony(self, action, target='', token=None):
        body = {'action': action, 'target': target}
        if token:
            body['token'] = token
        code, begin = self.call('/api/begin', body)
        self.assertEqual(code, 200)
        response = self.auth.response(begin, register=action == 'enroll')
        code, result = self.call('/api/finish', {'ceremony_id': begin['ceremony_id'], 'response': response})
        self.assertEqual(code, 200)
        return result

    def test_real_browser_protocol_enroll_login_approve_list_and_revoke(self):
        self.assertEqual(self.call('/api/data')[0], 403)
        _, session = self.call('/api/session')
        self.csrf = session['csrf']
        self.ceremony('enroll', token=self.server.store.bootstrap('owner'))
        self.assertEqual(self.call('/api/data')[0], 403)
        self.ceremony('login')
        value = {'agent': 'openclaw', 'project': 'test', 'plan': 'a' * 32, 'spec_hash': 'b' * 64,
                 'policy': 'c' * 64, 'scope': {'operations': ['apply'], 'egress': False, 'services': {}},
                 'mode': 'persistent', 'lifetime': 3600, 'sandbox': False}
        request = self.server.store.propose(value)
        code, data = self.call('/api/data')
        self.assertEqual(code, 200)
        self.assertEqual(data['requests'][0]['request_id'], request['request_id'])
        self.ceremony('approve', request['request_id'])
        self.assertEqual(self.server.store.check(value)['status'], 'authorized')
        _, data = self.call('/api/data')
        self.ceremony('revoke', data['grants'][0]['id'])
        self.assertEqual(self.server.store.check(value)['status'], 'needs_approval')

    def test_host_origin_csrf_and_agent_flags_cannot_authorize(self):
        _, session = self.call('/api/session')
        self.csrf = session['csrf']
        for extra in ({'Origin': 'https://evil.invalid'}, {'Host': 'evil.invalid'}, {'X-CSRF-Token': 'forged'}):
            self.assertEqual(self.call('/api/begin', {'action': 'login'}, extra)[0], 403)
        self.assertEqual(self.call('/api/finish', {'approved': True})[0], 403)
        self.assertEqual(self.call('/api/data')[0], 403)

    def test_active_agents_remain_visible_after_large_revoked_history(self):
        _, session = self.call('/api/session'); self.csrf = session['csrf']
        self.ceremony('enroll', token=self.server.store.bootstrap('owner'))
        self.ceremony('login')
        with self.server.store.db() as db:
            for i in range(65):
                db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                           ('old-' + str(i), 'a'*64, 'old', 'owner', None, i, 'revoked'))
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       ('current-agent', 'b'*64, 'active', 'owner', None, 100, 'active'))
        code, data = self.call('/api/data')
        self.assertEqual(code, 200)
        self.assertEqual(data['agents'][0]['id'], 'current-agent')
        self.ceremony('unpair', 'current-agent')
        self.assertEqual(self.call('/api/data')[0], 200)

    def test_signed_agent_pairing_then_fresh_browser_passkey(self):
        _, session = self.call('/api/session'); self.csrf = session['csrf']
        self.ceremony('enroll', token=self.server.store.bootstrap('owner'))
        key = Ed25519PrivateKey.generate(); public = agents.public_key(key)
        value = {'agent': agents.identity(public), 'public_key': public, 'audience': RP,
                 'operation': 'pair', 'label': '<untrusted device label>',
                 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}
        raw = schema.canonical(value).encode()
        headers = {'Host': RP, 'Content-Type': 'application/json', 'X-Agent-Signature': agents.sign(raw,key)}
        def post(extra=None):
            client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
            client.request('POST', '/agent/pair', raw, {**headers, **(extra or {})})
            response = client.getresponse(); result = response.status, json.loads(response.read())
            client.close(); return result
        self.assertEqual(post({'Origin': 'https://evil.invalid'})[0], 403)
        code, result = post(); self.assertEqual(code, 200)
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(post()[0], 403)  # nonce replay, even before approval
        self.assertEqual(self.call('/api/data')[0], 403)
        self.ceremony('login')
        _, data = self.call('/api/data')
        self.assertEqual(data['pairings'][0]['label'], value['label'])
        self.assertIn('fingerprint', data['pairings'][0])
        self.assertNotIn('public_key', data['pairings'][0])
        self.ceremony('pair', result['approval_url'].split('/')[-1])
        self.assertEqual(self.server.store.paired(value['agent'], public, RP)['status'], 'paired')
        with self.assertRaises(Exception):
            self.server.store.inventory_access(value['agent'])


if __name__ == '__main__':
    unittest.main()
