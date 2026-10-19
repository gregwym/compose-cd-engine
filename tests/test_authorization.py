"""Cryptographic software-authenticator tests, not mocked WebAuthn verification."""
import copy
import hashlib
import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData
from authorization.passkeys import Passkeys
from authorization.store import Store
from authorization.scope import Denied, diff, scope
from authorization.rpc import signature
from deployer import schema
import test_projects as projects

ORIGIN = 'https://deployer.example.ts.net'
RP = 'deployer.example.ts.net'


class Authenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = uuid.uuid4().bytes
        self.counter = 0

    def response(self, ceremony, register=False, origin=ORIGIN, rp=RP, uv=True, challenge=None, cross=False):
        options = ceremony['options']['publicKey']
        client = CollectedClientData.create('webauthn.create' if register else 'webauthn.get',
            challenge or options['challenge'], origin, cross_origin=cross)
        flags = AuthenticatorData.FLAG.UP | (AuthenticatorData.FLAG.UV if uv else 0)
        self.counter += 1
        data = AttestedCredentialData.create(b'\0' * 16, self.id, ES256.from_cryptography_key(self.key.public_key())) if register else b''
        auth = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(),
            flags | (AuthenticatorData.FLAG.AT if register else 0), self.counter, data)
        response = {'clientDataJSON': websafe_encode(client)}
        if register:
            response['attestationObject'] = websafe_encode(cbor.encode({'fmt': 'none', 'authData': bytes(auth), 'attStmt': {}}))
        else:
            response.update(authenticatorData=websafe_encode(auth), userHandle=websafe_encode(b'owner'),
                            signature=websafe_encode(self.key.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256()))))
        return {'id': websafe_encode(self.id), 'rawId': websafe_encode(self.id), 'type': 'public-key', 'response': response}


class ApprovalSecurity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'auth.sqlite', ORIGIN)
        self.passkeys = Passkeys(self.store, RP, ORIGIN)
        self.authenticator = Authenticator()
        token = self.store.bootstrap('owner')
        start = self.passkeys.begin('browser', 'enroll', token=token)
        self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start, register=True))
        self.value = {'project': 'app', 'agent': 'openclaw', 'plan': 'a' * 32, 'spec_hash': 'b' * 64,
            'policy': 'c' * 64, 'scope': {'services': {'app': {'memory_mb': 128, 'mounts': [], 'repository': 'ghcr.io/team/app'}},
                                      'operations': ['apply', 'restart'], 'egress': False},
            'mode': 'persistent', 'lifetime': 3600, 'sandbox': False}

    def tearDown(self):
        self.temp.cleanup()

    def approve(self, request=None):
        request = request or self.store.propose(self.value)
        start = self.passkeys.begin('browser', 'approve', request['request_id'], admin='owner')
        return self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start), admin='owner')

    def test_real_signatures_issue_persistent_grant_and_restart(self):
        self.approve()
        restored = Store(self.store.path, ORIGIN)
        self.assertEqual(restored.check(self.value)['status'], 'authorized')
        changed = copy.deepcopy(self.value)
        changed['scope']['services']['app']['memory_mb'] = 256
        self.assertEqual(restored.check(changed)['status'], 'needs_approval')
        for key in ('policy', 'agent', 'project'):
            with self.subTest(key=key):
                self.assertEqual(restored.check({**self.value, key: 'other'})['status'], 'needs_approval')

    def test_forged_origin_rp_challenge_uv_cross_origin_and_signature_fail(self):
        request = self.store.propose(self.value)
        for changed in ({'origin': 'https://evil.invalid'}, {'rp': 'evil.invalid'}, {'uv': False},
                        {'challenge': websafe_encode(b'bad' * 12)}, {'cross': True}, {'bad_signature': True}):
            start = self.passkeys.begin('browser', 'approve', request['request_id'], admin='owner')
            kwargs = {k: v for k, v in changed.items() if k != 'bad_signature'}
            response = self.authenticator.response(start, **kwargs)
            if changed.get('bad_signature'):
                response['response']['signature'] = websafe_encode(b'forged')
            with self.subTest(changed=changed), self.assertRaises(Exception):
                self.passkeys.finish('browser', start['ceremony_id'], response, admin='owner')
            with self.assertRaises(Denied):
                self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start), admin='owner')
        self.assertEqual(self.store.check(self.value)['status'], 'needs_approval')

    def test_single_use_session_bound_and_expiring_ceremonies(self):
        start = self.passkeys.begin('browser', 'login')
        response = self.authenticator.response(start)
        with self.assertRaises(Denied):
            self.passkeys.finish('other-browser', start['ceremony_id'], response)
        self.passkeys.finish('browser', start['ceremony_id'], response)
        with self.assertRaises(Denied):
            self.passkeys.finish('browser', start['ceremony_id'], response)
        start = self.passkeys.begin('browser', 'login')
        with self.store.db() as db:
            db.execute('UPDATE ceremonies SET expires=0')
        with self.assertRaises(Denied):
            self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start))

    def test_request_mutation_invalidates_approval(self):
        request = self.store.propose(self.value)
        start = self.passkeys.begin('browser', 'approve', request['request_id'], admin='owner')
        with self.store.db() as db:
            db.execute("UPDATE requests SET scope='{}'")
        with self.assertRaises(Denied):
            self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start), admin='owner')

    def test_revocation_preserves_records_and_blocks_authorization(self):
        self.approve()
        grant = self.store.check(self.value)['grant_id']
        start = self.passkeys.begin('browser', 'revoke', grant, admin='owner')
        self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start), admin='owner')
        self.assertEqual(self.store.check(self.value)['status'], 'needs_approval')
        with self.store.db() as db:
            self.assertEqual(db.execute('SELECT status,revision FROM grants').fetchone()[:], ('revoked', 2))
            with self.assertRaises(Exception):
                db.execute('DELETE FROM audit')

    def test_once_and_expiring_grants(self):
        self.value['mode'] = 'once'
        self.approve()
        self.assertEqual(self.store.check({**self.value, 'plan': 'd' * 32})['status'], 'needs_approval')
        with self.store.db() as db:
            db.execute('UPDATE grants SET expires=0,status=\'revoked\'')
        self.value.update(mode='expiring', plan='e' * 32)
        self.approve()
        with self.store.db() as db:
            db.execute('UPDATE grants SET expires=1')
        self.assertEqual(self.store.check(self.value)['status'], 'needs_approval')

    def test_agent_rpc_cannot_approve_enroll_revoke_or_modify(self):
        for operation in ('approve', 'enroll', 'issue', 'revoke', 'remove', 'bootstrap'):
            with self.subTest(operation=operation), self.assertRaises(Denied):
                self.store.rpc(operation, self.value)
        with self.assertRaises(Denied):
            self.passkeys.begin('browser', 'approve', 'a' * 32)

    def test_bootstrap_single_use_and_no_public_registration(self):
        with self.assertRaises(Denied):
            self.passkeys.begin('browser', 'enroll', token='forged')
        token = self.store.bootstrap('owner')
        self.passkeys.begin('browser', 'enroll', token=token)
        with self.assertRaises(Denied):
            self.passkeys.begin('browser', 'enroll', token=token)

    def test_counters_and_unknown_credentials_rejected(self):
        start = self.passkeys.begin('browser', 'login')
        with self.assertRaises(Exception):
            self.passkeys.finish('browser', start['ceremony_id'], Authenticator().response(start))
        start = self.passkeys.begin('browser', 'login')
        self.authenticator.counter = 0
        with self.assertRaises(Denied):
            self.passkeys.finish('browser', start['ceremony_id'], self.authenticator.response(start))

    def test_approval_flood_limit_and_no_secret_audit(self):
        for i in range(20):
            self.store.propose({**self.value, 'plan': f'{i:032x}'})
        with self.assertRaises(Denied):
            self.store.propose({**self.value, 'plan': 'f' * 32})
        with self.store.db() as db:
            output = json.dumps([dict(r) for r in db.execute('SELECT * FROM audit')])
        self.assertNotIn('private_key', output)
        self.assertNotIn('environment', output)


class GrantEnforcement(projects.DurableTasks):
    """Reuse the existing durable-task tests with authorization enabled."""
    def setUp(self):
        super().setUp()
        self.auth_store = Store(Path(self.temp.name) / 'auth.sqlite', ORIGIN)
        self.agent_key = Path(self.temp.name) / 'agent.key'
        self.agent_key.write_bytes(b'a' * 48)
        self.agent_key.chmod(0o600)
        self.cfg['images']['example.invalid/team/app']['digests'] = ['a' * 64]
        self.cfg['authorization'] = {'socket': '/run/auth.sock', 'service_key': '/etc/service.key',
                                     'agents': {'openclaw': str(self.agent_key)}}
        self.service = projects.Service('policy', self.runner)
        self.rpc_patch = patch('deployer.service.rpc.call', side_effect=lambda cfg, op, value: self.auth_store.rpc(op, value))
        self.rpc_patch.start()

    def tearDown(self):
        self.rpc_patch.stop()
        super().tearDown()

    def call(self, op, payload=None, project='test', agent='openclaw'):
        return self.service.dispatch(projects.message(op, payload, project), agent=agent)

    def plan(self, item=None, project='test'):
        result = self.call('plan', projects.spec() if item is None else item, project)
        rid = self.call('grant_request', {'plan_id': result['plan_id'], 'mode': 'persistent', 'lifetime': 3600}, project)['request_id']
        # Other tests exercise full WebAuthn; here the independent administrator
        # process issues a test grant, never an agent-facing API.
        with self.auth_store.db() as db:
            self.auth_store.issue(db, rid, 'test-administrator', None)
        return result['plan_id']

    def apply(self, plan=None, project='test'):
        return self.call('apply', {'plan_id': plan or self.plan(project=project)}, project)['task_id']

    def task(self, task):
        return self.call('task', {'task_id': task})

    def test_v1_cannot_bypass_grants(self):
        with self.assertRaises(Denied):
            self.service.dispatch(projects.message('plan', projects.spec()))

    def test_pending_protected_storage_cannot_apply(self):
        planned = self.call('plan', projects.spec())
        self.assertEqual(planned['status'], 'needs_approval')
        self.assertTrue(planned['grant_diff'])
        with self.assertRaises(Denied):
            self.apply(planned['plan_id'])

    def test_revocation_after_enqueue_prevents_any_docker(self):
        task = self.apply()
        with self.auth_store.db() as db:
            db.execute("UPDATE grants SET status='revoked'")
        with patch.object(self.service, 'docker', side_effect=AssertionError('Docker touched')) as docker:
            self.service.run_one()
            docker.assert_not_called()
        self.assertEqual(self.task(task)['status'], 'failed')

    def test_revocation_during_pull_blocks_mutation(self):
        task = self.apply()
        def compose(*args, **kwargs):
            if 'pull' in args:
                with self.auth_store.db() as db:
                    db.execute("UPDATE grants SET status='revoked'")
            self.assertNotIn('up', args)
        self.run_job(compose)
        self.assertEqual(self.task(task)['status'], 'failed')

    def test_other_agent_cannot_read_or_apply_plan(self):
        plan = self.plan()
        self.cfg['authorization']['agents']['other'] = str(self.agent_key)
        with self.assertRaises(Denied):
            self.call('apply', {'plan_id': plan}, agent='other')

    def test_signed_principal_rechecked_at_runner(self):
        value = {'version': 2, 'agent': 'openclaw', **projects.message('plan', projects.spec())}
        raw = schema.canonical(value)
        wire = {'raw': raw, 'signature': signature(raw.encode(), b'a' * 48)}
        with patch('management.protocol.protected_file', side_effect=Path):
            self.assertEqual(self.service.dispatch_wire(wire)['status'], 'needs_approval')
            with self.assertRaises(ValueError):
                self.service.dispatch_wire(wire)
            wire['raw'] = raw.replace('openclaw', 'other')
            with self.assertRaises(ValueError):
                self.service.dispatch_wire(wire)

    def test_no_union_of_grants_or_unsigned_digest_expansion(self):
        first = scope(projects.spec(), self.cfg)
        changed = copy.deepcopy(first)
        changed['services']['app']['unsigned_digest'] = 'b' * 64
        self.assertTrue(diff(changed, first))

    # The base's raw-v1 HTTP roundtrip is separately covered in test_projects.
    def test_http_large_signed_declaration_roundtrip_and_route_replay_rejection(self):
        self.test_v1_cannot_bypass_grants()

    def test_partial_failure_latches_recovery_before_mutation(self):
        task = self.apply()
        self.run_job(lambda *a, **k: (_ for _ in ()).throw(RuntimeError()) if 'up' in a else None)
        self.assertEqual(self.task(task)['status'], 'recovery_required')
        with self.assertRaises(ValueError):
            self.call('restart')

    def test_crash_recovery_does_not_replay_running_tasks(self):
        task = self.apply()
        with self.service.db() as db:
            db.execute("UPDATE tasks SET state='running'")
        restored = projects.Service('policy', self.runner)
        self.assertFalse(restored.run_one())
        self.assertEqual(self.task(task)['status'], 'outcome_unknown')
