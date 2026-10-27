"""Offline signed Runner -> real Store -> software Passkey grant continuation."""
import json
import urllib.error
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from scripts.agent import Client
from scripts.task_delegation import TaskGrantWorkflow, main
import test_task_delegation as combined


class Follow(combined.Combined):
    # Reuse setup, not the inherited task/mutation acceptance tests.
    def setUp(self):
        super().setUp()
        self.path = Path(self.temp.name) / 'grant.json'
        pem = self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.client = Client('https://deployer.example.ts.net', self.agent, 'existing-app', pem)
        self.calls, self.events = [], []
        test = self
        class Response:
            def __init__(self, value): self.value = value
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return json.dumps(self.value).encode()
        class Opener:
            def open(self, request, timeout):
                value = json.loads(request.data)
                test.calls.append(value['operation'])
                try:
                    result = test.service.dispatch_wire({'raw': request.data.decode(),
                        'signature': request.get_header('X-management-signature')})
                except combined.Denied:
                    raise urllib.error.HTTPError(request.full_url, 403, 'denied', {}, None)
                return Response(result)
        self.client.opener = Opener()

    def flow(self, **kw):
        return TaskGrantWorkflow(self.client, self.path, emit=self.events.append, **kw)

    def waiting(self):
        flow = self.flow()
        event = flow.step()
        self.assertEqual(event['status'], 'authorization_required')
        self.assertEqual(event['scope']['type'], 'registered_task_v1')
        self.rid = event['request_id']
        return flow

    def approve_exact(self):
        start = self.passkeys.begin('owner', 'approve', self.rid, admin='owner')
        self.passkeys.finish('owner', start['ceremony_id'], self.owner.response(start), admin='owner')
        with self.store.db() as db:
            return db.execute('SELECT id FROM grants WHERE request=?', (self.rid,)).fetchone()[0]

    def test_follow_approves_exact_request_no_mutation_or_message(self):
        flow = self.waiting()
        def owner(event):
            self.events.append(event)
            if event['status'] == 'waiting_for_authorization': self.gid = self.approve_exact()
        flow.emit = owner
        with patch('scripts.agent.time.sleep'):
            self.assertEqual(flow.run(True, timeout=10, interval=1), 0)
        self.assertEqual(self.events[-1]['delegation_id'], self.gid)
        self.assertEqual(json.loads(self.path.read_text())['delegation_id'], self.gid)
        self.assertEqual(self.flow().step()['delegation_id'], self.gid)
        self.assertEqual(self.calls.count('delegation_request'), 1)
        self.assertEqual(set(self.calls), {'delegation_request', 'grant_status'})
        for path in (self.path, self.path.with_name('grant.json.lock')):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('must-not-return', self.path.read_text()+json.dumps(self.events))

    def test_pending_timeout_resume_keeps_original_lifetime_no_replacement(self):
        flow = self.waiting()
        self.assertEqual(flow.run(False), 75)
        with patch('scripts.agent.time.monotonic', side_effect=[0, 2]):
            self.assertEqual(flow.run(True, timeout=1), 75)
        gid = self.approve_exact()
        self.assertEqual(self.flow(lifetime=600).step()['delegation_id'], gid)
        self.assertEqual(self.calls.count('delegation_request'), 1)
        self.assertEqual(json.loads(self.path.read_text())['lifetime'], 3600)

    def test_revoked_expired_unpaired_and_credential_deactivated_do_not_succeed(self):
        for state, expected in [('revoked','revoked'), ('expired','expired'),
                                ('unpaired','access_denied_or_unpaired'), ('credential','not_authorized')]:
            with self.subTest(state=state):
                self.path = Path(self.temp.name) / (state+'.json')
                flow = self.waiting(); gid = self.approve_exact()
                with self.store.db() as db:
                    if state == 'revoked': db.execute("UPDATE grants SET status='revoked' WHERE id=?", (gid,))
                    if state == 'expired': db.execute('UPDATE grants SET expires=1 WHERE id=?', (gid,))
                    if state == 'unpaired': db.execute("UPDATE paired_agents SET status='revoked'")
                    if state == 'credential': db.execute('UPDATE credentials SET active=0')
                self.assertEqual(flow.step()['status'], expected)
                n = len(self.calls)
                self.assertEqual(self.flow().step()['status'], expected)
                self.assertEqual(len(self.calls), n)
                with self.store.db() as db:
                    db.execute("UPDATE paired_agents SET status='active'")
                    db.execute('UPDATE credentials SET active=1')

    def test_denial_and_request_expiry_stop_without_renewal(self):
        for state in ('denied', 'expired'):
            self.path = Path(self.temp.name) / (state+'.json')
            flow = self.waiting()
            with self.store.db() as db:
                db.execute('UPDATE requests SET status=? WHERE id=?', (state,self.rid))
            self.assertEqual(flow.step()['status'],state)
            n = len(self.calls); self.flow().step(); self.assertEqual(len(self.calls), n)

    def test_ambiguous_request_loss_or_crash_never_replaces(self):
        original = self.client.call
        def lost(op, payload):
            original(op, payload)
            raise OSError('lost after server commit')
        self.client.call = lost
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.client.call = original
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.assertEqual(self.calls, ['delegation_request'])
        self.path = Path(self.temp.name) / 'crash.json'
        flow = self.flow(); flow.state['phase'] = 'request_intent'; flow.save()
        self.assertEqual(self.flow().step()['status'], 'outcome_unknown')
        self.assertEqual(self.calls, ['delegation_request'])

    def test_every_binding_field_and_missing_delegation_rejected(self):
        for field in ('request_id','plan_id','policy','spec_hash','scope','agent','project','mode','lifetime','delegation_id'):
            self.path = Path(self.temp.name) / (field+'.json')
            flow = self.waiting(); self.approve_exact()
            original = self.client.call
            def altered(op, payload):
                result = original(op, payload)
                if field == 'delegation_id': result.pop(field)
                elif field == 'scope': result[field] = dict(result[field], diagnostics='changed')
                elif field == 'lifetime': result[field] = 600
                else: result[field] = 'f'*32
                return result
            self.client.call = altered
            self.assertEqual(flow.step()['status'], 'invalid_response_or_binding', field)
            self.client.call = original

    def test_unrelated_approved_grant_cannot_satisfy_pending_request(self):
        self.waiting(); gid = self.approve_exact()
        self.path = Path(self.temp.name) / 'other.json'
        flow = self.waiting()
        self.assertEqual(flow.step()['status'], 'waiting_for_authorization')
        self.assertNotIn('delegation_id', self.client.call('grant_status', {'approval_id':self.rid}))

    def test_private_state_lock_identity_and_bounds(self):
        flow = self.flow()
        for field in ('endpoint','agent','project'):
            original = getattr(self.client,field); setattr(self.client,field,'other')
            with self.assertRaises(ValueError): self.flow()
            setattr(self.client,field,original)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): self.flow()
        self.path.chmod(0o600)
        self.path.parent.chmod(0o755)
        with self.assertRaises(ValueError): self.flow()
        self.path.parent.chmod(0o700)
        with flow.locked():
            with self.assertRaises(BlockingIOError): self.flow()
        for kw in ({'timeout':0},{'timeout':86401},{'interval':0},{'interval':301}):
            with self.assertRaises(ValueError): flow.run(True, **kw)
        self.path.unlink(); target=self.path.parent/'target'; target.write_text('private');target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(ValueError): self.flow()
        self.path.unlink(); lock=self.path.with_name('grant.json.lock');lock.unlink();lock.symlink_to(target)
        with self.assertRaises(OSError): self.flow()
        self.assertEqual(self.calls, [])

    def test_old_request_response_unchanged_and_service_cannot_issue(self):
        req = self.store.propose({'project':'app','agent':self.agent,'plan':'a'*32,
            'spec_hash':'b'*64,'policy':'c'*64,'scope':{'operations':['inspect']},
            'mode':'persistent','lifetime':3600,'sandbox':False})
        self.assertEqual(self.store.rpc('request', {'agent':self.agent,'project':'app',
            'request_id':req['request_id']}), req)
        with self.assertRaises(combined.Denied): self.store.rpc('issue', {'request_id':req['request_id']})

    def test_completed_resume_revalidates_revocation(self):
        flow = self.waiting(); gid = self.approve_exact()
        self.assertEqual(flow.step()['delegation_id'], gid)
        with self.store.db() as db:
            db.execute("UPDATE grants SET status='revoked' WHERE id=?", (gid,))
        self.assertEqual(self.flow().step()['status'], 'revoked')
        self.assertEqual(self.calls.count('delegation_request'), 1)

    def test_status_failures_backoff_and_denial_are_bounded(self):
        flow = self.waiting()
        original = self.client.call
        self.client.call = lambda *_: (_ for _ in ()).throw(OSError('private'))
        with patch('scripts.agent.time.sleep'):
            self.assertEqual(flow.run(True), 75)
        self.assertEqual(json.loads(self.path.read_text())['phase'], 'waiting')
        self.client.call = lambda *_: (_ for _ in ()).throw(
            urllib.error.HTTPError(self.client.endpoint, 429, 'private', {'Retry-After':'120'}, None))
        self.assertEqual(flow.run(True), 75)
        self.assertEqual(self.events[-1]['status'], 'retry_later')
        self.client.call = original
        self.approve_exact()
        self.assertEqual(self.flow().run(), 0)

    def test_cli_follow_dispatch_and_missing_state(self):
        pem = self.client.key
        argv = ['task', '--endpoint', self.client.endpoint, '--key', '/unused',
                '--project', self.client.project, 'request', '--follow', '--state', str(self.path),
                '--timeout', '10', '--interval', '1']
        with patch('sys.argv', argv), patch('scripts.task_delegation.private', return_value=pem), patch(
                'scripts.task_delegation.TaskGrantWorkflow') as flow:
            flow.return_value.run.return_value = 75
            self.assertEqual(main(), 75)
            flow.return_value.run.assert_called_once_with(True, 10, 1)
        with patch('sys.argv', argv[:7]+['request','--follow']), patch(
                'scripts.task_delegation.private', return_value=pem):
            with self.assertRaises(ValueError): main()

    def test_store_rejects_grant_binding_tamper_without_fallback(self):
        for field, changed in [('plan','f'*32), ('policy','f'*64), ('scope','{}'),
                               ('project','other'), ('agent','other'), ('mode','persistent'),
                               ('expires',1)]:
            self.path = Path(self.temp.name) / (field+'.json')
            flow = self.waiting(); gid = self.approve_exact()
            with self.store.db() as db:
                db.execute('UPDATE grants SET '+field+'=? WHERE id=?', (changed,gid))
            self.assertNotEqual(flow.step()['status'], 'success', field)

    def test_request_and_grant_counts_are_exactly_one(self):
        flow = self.waiting(); gid = self.approve_exact()
        self.assertEqual(flow.step()['delegation_id'], gid)
        with self.store.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM requests').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM grants').fetchone()[0],1)


# Reuse the real fixture without rerunning unrelated mutation acceptance tests.
for base in (combined.Combined, combined.Transactions):
    for name in vars(base):
        if name.startswith('test_') and name not in Follow.__dict__:
            setattr(Follow, name, None)
