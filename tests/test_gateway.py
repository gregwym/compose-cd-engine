"""Gateway over real HTTP with a software Passkey and a fake runner."""
import hashlib
import hmac
import http.client
import json
import time
import unittest
from unittest import mock
from helpers import HOST, Agent, Stack


class Gateway(unittest.TestCase):
    def setUp(self):
        self.stack = Stack()
        self.stack.enroll()
        self.agent = self.stack.agent

    def tearDown(self):
        self.stack.close()

    def fresh(self):
        from helpers import Browser
        return Browser(self.stack.port, self.stack.authenticator)

    def test_enrollment_code_is_single_use_and_stops_after_enrollment(self):
        self.assertIsNone(self.stack.store.enrollment_code())
        status, result = self.fresh().request('POST', '/api/begin', {'action': 'enroll', 'token': 'guess'})
        self.assertEqual(result['error'], 'invalid_enrollment_code')

    def test_unpaired_agent_can_only_ask_to_pair(self):
        self.assertEqual(self.agent.error('projects'), 'not_paired')
        pending = self.agent('pair', label='openclaw')
        self.assertEqual(pending['status'], 'pending')
        self.assertIn('/p/', pending['approval_url'])
        status, page = self.stack.browser.request('GET', '/api/pairing/' + pending['approval_url'].rsplit('/', 1)[1])
        self.assertEqual(page['fingerprint'], pending['fingerprint'])
        self.assertEqual(self.agent.error('projects'), 'not_paired')

    def test_pairing_grants_read_only(self):
        self.stack.pair()
        self.assertEqual(self.agent('pair', label='openclaw')['status'], 'paired')
        listed = self.agent('projects')['projects']
        self.assertEqual(listed[0]['project'], 'app')
        self.assertIsNone(listed[0]['operate_until'])
        self.assertEqual(self.agent('logs', project='app')['logs'], {'app-web-1': 'hello\n'})
        self.assertEqual(self.agent.error('restart', project='app'), 'not_authorized')
        self.assertEqual(self.agent.error('read', project='app'), 'not_authorized')
        self.assertNotIn('lifecycle', self.stack.runner.ops())

    def test_operate_grant_allows_lifecycle_with_approved_identity(self):
        self.stack.pair()
        request = self.agent('request', kind='operate', project='app', days=3)
        self.assertEqual(request['status'], 'pending')
        self.assertEqual(self.agent.error('restart', project='app'), 'not_authorized')
        decided = self.stack.approve(request)
        self.assertEqual(decided['status'], 'approved')
        self.assertIn('grant', decided['outcome'])
        job = self.agent('restart', project='app', services=['web'])['job']
        self.assertEqual(self.stack.wait_job(job)['status'], 'success')
        op, args = self.stack.runner.calls[-1]
        self.assertEqual((op, args['action'], args['services']), ('lifecycle', 'restart', ['web']))
        self.assertEqual(args['identity'], self.stack.runner.identity)
        self.assertEqual(self.agent('read', project='app')['env_keys'], ['TOKEN'])
        until = self.agent('whoami')['grants'][0]['expires']
        self.assertAlmostEqual(until, time.time() + 3 * 86400, delta=60)

    def test_approval_is_bound_and_single_use(self):
        self.stack.pair()
        request = self.agent('request', kind='operate', project='app')
        self.stack.approve(request)
        status, result = self.stack.browser.request('POST', '/api/begin', {'action': 'approve', 'target': request['id']})
        self.assertEqual(result['error'], 'stale_request')
        grants = self.stack.store.grants()
        self.assertEqual(len(grants), 1)

    def test_request_changing_after_ceremony_start_is_rejected(self):
        self.stack.pair()
        request = self.agent('request', kind='operate', project='app')
        browser = self.stack.browser
        status, start = browser.request('POST', '/api/begin', {'action': 'approve', 'target': request['id']})
        with self.stack.store.db() as db:
            db.execute('UPDATE requests SET detail=? WHERE id=?', ('{"identity":{},"lifetime":2592000}', request['id']))
        status, result = browser.request('POST', '/api/finish', {'ceremony_id': start['ceremony_id'],
                                         'response': self.stack.authenticator.response(start)})
        self.assertEqual(result['error'], 'stale_request')
        self.assertEqual(self.agent('request_status', id=request['id'])['status'], 'pending')

    def test_wrong_passkey_and_wrong_origin_fail(self):
        from helpers import Authenticator
        self.stack.pair()
        request = self.agent('request', kind='operate', project='app')
        browser = self.stack.browser
        status, start = browser.request('POST', '/api/begin', {'action': 'approve', 'target': request['id']})
        status, result = browser.request('POST', '/api/finish', {'ceremony_id': start['ceremony_id'],
                                         'response': Authenticator().response(start)})
        self.assertEqual(result['error'], 'verification_failed')
        status, start = browser.request('POST', '/api/begin', {'action': 'approve', 'target': request['id']})
        status, result = browser.request('POST', '/api/finish', {'ceremony_id': start['ceremony_id'],
                                         'response': self.stack.authenticator.response(start, origin='https://evil.example')})
        self.assertEqual(result['error'], 'verification_failed')
        status, result = browser.request('POST', '/api/begin', {'action': 'approve', 'target': request['id']},
                                         origin='https://evil.example')
        self.assertEqual(result['error'], 'wrong_origin')
        self.assertEqual(self.agent('request_status', id=request['id'])['status'], 'pending')

    def test_change_runs_planned_apply_and_hides_env_values(self):
        self.stack.pair()
        request = self.agent('request', kind='change', project='app', compose='services: {web: {}}\n',
                             env_set={'TOKEN': 'secret-value'})
        self.assertEqual(request['detail']['plan']['env_set'], ['TOKEN'])
        for key in ('diff', 'highlights'):  # previews for agents carry no file content or interpolated values
            self.assertNotIn(key, request['detail']['plan'])
            self.assertNotIn(key, self.agent('request_status', id=request['id'])['detail']['plan'])
        self.assertIn('diff', self.stack.browser.request('GET', '/api/request/' + request['id'])[1]['detail']['plan'])
        status, page = self.stack.browser.request('GET', '/api/request/' + request['id'])
        self.assertNotIn('secret-value', json.dumps(page))
        decided = self.stack.approve(request)
        self.assertEqual(self.stack.wait_job(decided['outcome']['job'])['status'], 'success')
        op, args = self.stack.runner.calls[-1]
        self.assertEqual(op, 'apply')
        self.assertEqual(args['plan']['env_set'], {'TOKEN': 'secret-value'})
        self.assertEqual(self.agent.error('restart', project='app'), 'not_authorized')

    def test_env_only_change_does_not_echo_current_compose_to_the_agent(self):
        self.stack.pair()
        request = self.agent('request', kind='change', project='app', env_set={'A': '1'})
        self.assertNotIn('compose', request['detail']['plan'])
        self.assertIn('compose', self.stack.browser.request('GET', '/api/request/' + request['id'])[1]['detail']['plan'])

    def test_runner_refusal_is_returned_and_no_request_created(self):
        from shared.wire import Denied
        self.stack.pair()

        def refuse(args):
            raise Denied('policy', ['web: privileged'])
        self.stack.runner.results['plan'] = refuse
        status, data = self.agent.send(self.agent.body('request', {'kind': 'change', 'project': 'app', 'compose': 'x'}))
        self.assertEqual((data['error'], data['detail']), ('policy', ['web: privileged']))
        self.assertEqual(self.stack.store.dashboard()['requests'], [])

    def test_create_issues_grant_and_applies(self):
        self.stack.pair()
        request = self.agent('request', kind='create', project='newapp', compose='services: {}\n')
        identity = request['detail']['plan']['identity']
        self.assertEqual(identity['working_dir'], '/volume1/docker/newapp')
        decided = self.stack.approve(request)
        self.assertEqual(self.stack.wait_job(decided['outcome']['job'])['status'], 'success')
        self.assertEqual(self.agent('whoami')['grants'][0]['project'], 'newapp')

    def test_failed_and_rolled_back_jobs_are_reported(self):
        self.stack.pair()
        self.stack.approve(self.agent('request', kind='operate', project='app'))
        self.stack.runner.results['lifecycle'] = {'status': 'rolled_back', 'error': 'unhealthy', 'detail': 'web: exited'}
        state = self.stack.wait_job(self.agent('update', project='app')['job'])
        self.assertEqual((state['status'], state['result']['detail']), ('rolled_back', 'web: exited'))

    def test_revoke_and_unpair(self):
        self.stack.pair()
        self.stack.approve(self.agent('request', kind='operate', project='app'))
        grant = self.stack.store.grants()[0]
        self.assertEqual(self.stack.browser.passkey('revoke', grant['id'])[0], 200)
        self.assertEqual(self.agent.error('restart', project='app'), 'not_authorized')
        self.stack.approve(self.agent('request', kind='operate', project='app'))
        pending = self.agent('request', kind='down', project='app')
        self.assertEqual(self.stack.browser.passkey('unpair', self.agent.id)[0], 200)
        self.assertEqual(self.agent.error('projects'), 'not_paired')
        self.assertEqual(self.stack.store.grants(), [])
        self.assertEqual(self.stack.store.request(pending['id'])['status'], 'denied')

    def test_agent_cannot_see_other_agents_requests_or_jobs(self):
        self.stack.pair()
        other = Agent(self.stack.port)
        self.stack.pair(other)
        request = self.agent('request', kind='operate', project='app')
        self.assertEqual(other.error('request_status', id=request['id']), 'not_found')
        self.stack.approve(request)
        job = self.agent('restart', project='app')['job']
        self.assertEqual(other.error('job', id=job), 'not_found')
        self.assertEqual(other.error('restart', project='app'), 'not_authorized')

    def test_signature_replay_audience_and_clock(self):
        self.stack.pair()
        body = self.agent.body('whoami')
        self.assertEqual(self.agent.send(body)[0], 200)
        self.assertEqual(self.agent.send(body)[1]['error'], 'replay')
        self.assertEqual(self.agent.send(self.agent.body('whoami', audience='other.ts.net'))[1]['error'], 'wrong_audience')
        self.assertEqual(self.agent.send(self.agent.body('whoami', timestamp=int(time.time()) - 600))[1]['error'], 'clock_skew')
        forged = Agent(self.stack.port)
        body = self.agent.body('whoami')
        self.assertEqual(self.agent.send(body, 'ed25519=' + forged.key.sign(b'x').hex())[1]['error'], 'invalid_signature')

    def test_dashboard_requires_owner_sign_in(self):
        browser = self.fresh()
        status, data = browser.request('GET', '/api/dashboard')
        self.assertEqual(data['error'], 'sign_in_required')
        self.assertEqual(browser.passkey('login')[0], 200)
        status, data = browser.request('GET', '/api/dashboard')
        self.assertEqual(status, 200)
        self.assertEqual(len(data['credentials']), 1)

    def test_last_passkey_cannot_be_removed(self):
        credential = self.stack.store.dashboard()['credentials'][0]
        status, result = self.stack.browser.passkey('remove_credential', credential.upper())
        self.assertEqual(result['error'], 'last_passkey')

    def test_wrong_host_is_refused(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.stack.port, timeout=5)
        connection.request('GET', '/api/session', headers={'Host': 'evil.example'})
        self.assertEqual(connection.getresponse().status, 403)

    def test_serve_route_needs_published_port_and_writes_config(self):
        self.stack.pair()
        self.assertEqual(self.agent.error('request', kind='serve', project='app', https_port=8444, target_port=9999),
                         'port_not_published')
        self.assertEqual(self.agent.error('request', kind='serve', project='app', https_port=443, target_port=8096),
                         'invalid_argument')
        decided = self.stack.approve(self.agent('request', kind='serve', project='app', https_port=8444, target_port=8096))
        self.assertEqual(decided['outcome']['url'], f'https://{HOST}:8444/')
        config = self.stack.serve_configs[-1]
        handler = config['Web'][f'{HOST}:8444']['Handlers']['/']
        self.assertEqual(handler['Proxy'], 'http://host.docker.internal:8096')
        self.assertNotIn('AllowFunnel', config)
        self.assertEqual(self.agent('projects')['projects'][0]['routes'], [8444])
        self.assertEqual(self.stack.browser.passkey('remove_route', '8444')[0], 200)
        self.assertNotIn(f'{HOST}:8444', self.stack.serve_configs[-1]['Web'])

    def test_failed_execution_is_recorded(self):
        self.stack.pair()
        request = self.agent('request', kind='serve', project='app', https_port=8444, target_port=8096)
        with self.stack.store.db() as db:
            db.execute('INSERT INTO routes VALUES (8444, ?, 1, ?, 0)', ('other', 'x'))
        decided = self.stack.approve(request)
        self.assertEqual((decided['status'], decided['outcome']), ('approved', {'error': 'IntegrityError'}))

    def test_funnel_refused_falls_back_to_tailnet_only(self):
        tid = self.trigger()
        configs = []

        def apply(config):
            if 'AllowFunnel' in config:
                raise OSError('funnel not allowed')
            configs.append(config)
        self.stack.gateway.apply_serve = apply
        self.assertEqual(self.stack.gateway.sync_serve(), 'applied_without_funnel')
        self.assertIn(f'{HOST}:8443', configs[-1]['Web'])
        self.assertTrue(tid)

    def trigger(self):
        self.stack.pair()
        with mock.patch('gateway.triggers.github', return_value={'id': 42}):
            request = self.agent('request', kind='trigger', project='app', service='web', repository='owner/app',
                                 workflow='.github/workflows/docker.yml', branch='main', image='ghcr.io/owner/app')
        self.assertEqual(request['detail']['signer'],
                         'https://github.com/owner/app/.github/workflows/docker.yml@refs/heads/main')
        decided = self.stack.approve(request)
        return decided['outcome']['trigger']

    def test_trigger_requires_same_repository(self):
        self.stack.pair()
        with mock.patch('gateway.triggers.github', return_value={'id': 42}):
            error = self.agent.error('request', kind='trigger', project='app', service='web', repository='owner/app',
                                     workflow='.github/workflows/docker.yml', branch='main', image='ghcr.io/evil/app')
        self.assertEqual(error, 'repository_mismatch')

    def test_trigger_webhook_and_update(self):
        tid = self.trigger()
        self.assertTrue(self.stack.serve_configs[-1]['AllowFunnel'])
        with self.stack.store.db() as db:
            secret = db.execute('SELECT secret FROM triggers WHERE id=?', (tid,)).fetchone()['secret']
        payload = json.dumps({'action': 'completed', 'repository': {'id': 42}, 'workflow_run': {
            'conclusion': 'success', 'head_branch': 'main', 'path': '.github/workflows/docker.yml'}}).encode()

        def post(signature):
            connection = http.client.HTTPConnection('127.0.0.1', self.stack.hook_port, timeout=5)
            connection.request('POST', '/hooks/' + tid, payload, {'Content-Type': 'application/json',
                               'X-GitHub-Event': 'workflow_run', 'X-Hub-Signature-256': signature})
            return connection.getresponse().status
        self.assertEqual(post('sha256=' + '0' * 64), 403)
        self.stack.gateway.wake.clear()
        self.assertEqual(post('sha256=' + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()), 202)
        self.assertTrue(self.stack.gateway.wake.is_set())
        image = 'ghcr.io/owner/app@sha256:' + 'b' * 64
        with mock.patch('gateway.triggers.latest', return_value=('c' * 40, image)):
            self.stack.gateway.check_triggers(force=True)
            self.stack.gateway.check_triggers(force=True)
        updates = [args for op, args in self.stack.runner.calls if op == 'update_image']
        self.assertEqual(len(updates), 1)
        self.assertEqual((updates[0]['service'], updates[0]['image']), ('web', image))
        last = self.stack.store.dashboard()['triggers'][0]['last']
        self.assertEqual((last['image'], last['error']), (image, None))

    def test_trigger_secret_only_for_signed_in_owner(self):
        tid = self.trigger()
        browser = self.fresh()
        status, data = browser.request('GET', '/api/trigger/' + tid)
        self.assertEqual(data['error'], 'sign_in_required')
        browser.passkey('login')
        status, data = browser.request('GET', '/api/trigger/' + tid)
        self.assertEqual(data['url'], f'https://{HOST}:8443/hooks/{tid}')

    def test_restart_marks_interrupted_jobs_unknown(self):
        from gateway.store import Store
        jid = self.stack.store.create_job('agent-x', 'app', 'restart')
        self.assertEqual(Store(self.stack.store.path).job(jid)['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
