import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from authorization.server import Handler
from authorization.passkeys import Passkeys
from authorization.store import Store
from receiver.receiver import BoundedHTTPServer
from test_authorization import Authenticator, ORIGIN, RP


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


if __name__ == '__main__':
    unittest.main()
