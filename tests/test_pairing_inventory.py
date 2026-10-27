"""Real Ed25519 and software WebAuthn; no administrator keys on the agent."""
import copy
import json
import http.client
import socket
import threading
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authorization import agents
from authorization.pairing import INVENTORY_PROJECT, INVENTORY_SCOPE
from authorization.passkeys import Passkeys
from authorization.store import Store
from authorization.scope import Denied
from deployer.inventory import collect
from deployer import schema
from management import gateway, protocol
from receiver.receiver import BoundedHTTPServer
from test_authorization import Authenticator, ORIGIN, RP
import test_projects as projects


class PairingInventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'authorization.sqlite', ORIGIN)
        self.passkeys = Passkeys(self.store, RP, ORIGIN)
        self.owner = Authenticator()
        start = self.passkeys.begin('owner-session', 'enroll', token=self.store.bootstrap('owner'))
        self.passkeys.finish('owner-session', start['ceremony_id'], self.owner.response(start, register=True))
        self.key = Ed25519PrivateKey.generate()
        self.public = agents.public_key(self.key)
        self.agent = agents.identity(self.public)

    def tearDown(self):
        self.temp.cleanup()

    def ceremony(self, action, target):
        start = self.passkeys.begin('owner-session', action, target, admin='owner')
        return self.passkeys.finish('owner-session', start['ceremony_id'], self.owner.response(start), admin='owner')

    def pair(self, operation='pair', **changed):
        value = {'operation': operation, 'agent': self.agent, 'public_key': self.public,
                 'audience': RP, 'label': 'Kurisu Mac', 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time()), **changed}
        raw = schema.canonical(value).encode()
        return self.store.pair(raw, agents.sign(raw, self.key))

    def paired(self):
        result = self.pair()
        self.ceremony('pair', result['approval_url'].split('/')[-1])
        return result

    def grant(self, mode='persistent'):
        result = self.store.inventory_request({'agent': self.agent, 'mode': mode, 'lifetime': 3600})
        self.ceremony('approve', result['request_id'])
        return result

    def test_pairing_requires_passkey_and_grants_no_application_or_inventory_access(self):
        pending = self.pair()
        self.assertEqual(pending['status'], 'pending')
        with self.assertRaises(Denied):
            self.store.paired(self.agent, self.public, RP)
        with self.assertRaises(Denied):
            self.passkeys.begin('agent', 'pair', pending['approval_url'].split('/')[-1])
        self.ceremony('pair', pending['approval_url'].split('/')[-1])
        self.assertEqual(self.pair('pair_status')['status'], 'paired')
        self.assertEqual(self.store.paired(self.agent, self.public, RP)['status'], 'paired')
        with self.assertRaises(Denied):
            self.store.inventory_access(self.agent)
        self.assertEqual(self.store.check({'agent': self.agent, 'project': 'app', 'plan': 'x',
            'policy': 'policy', 'scope': {'operations': ['restart']}})['status'], 'needs_approval')

    def test_inventory_is_separate_revocable_and_survives_restart(self):
        self.paired(); self.grant()
        restored = Store(self.store.path, ORIGIN)
        self.assertEqual(restored.inventory_access(self.agent)['status'], 'authorized')
        with self.assertRaises(Denied):
            restored.inventory_access('another-agent')
        self.assertEqual(restored.check({'agent': self.agent, 'project': INVENTORY_PROJECT, 'plan': 'x',
            'policy': 'policy', 'scope': {'operations': ['restart']}})['status'], 'needs_approval')
        with restored.db() as db:
            grant = db.execute('SELECT id FROM grants').fetchone()[0]
        self.ceremony('revoke', grant)
        with self.assertRaises(Denied):
            restored.inventory_access(self.agent)

    def test_once_expiry_unpair_and_repair_do_not_restore_old_grants(self):
        self.paired(); self.grant('once')
        self.store.inventory_access(self.agent)
        with self.assertRaises(Denied):
            self.store.inventory_access(self.agent)
        self.grant('expiring')
        with self.store.db() as db:
            db.execute("UPDATE grants SET expires=1 WHERE status='active'")
        with self.assertRaises(Denied):
            self.store.inventory_access(self.agent)
        self.grant()
        pending = self.store.inventory_request({'agent': self.agent, 'mode': 'persistent', 'lifetime': 3600})
        self.ceremony('unpair', self.agent)
        with self.assertRaises(Denied):
            self.store.paired(self.agent, self.public, RP)
        with self.assertRaises(Denied):
            self.ceremony('approve', pending['request_id'])
        self.paired()
        with self.assertRaises(Denied):
            self.store.inventory_access(self.agent)

    def test_proof_of_possession_replay_staleness_and_audience(self):
        with self.assertRaises(ValueError):
            self.pair(public_key=agents.public_key(Ed25519PrivateKey.generate()))
        with self.assertRaises(ValueError):
            self.pair(timestamp=0)
        with self.assertRaises(Denied):
            self.pair(audience='other.example.ts.net')
        nonce = uuid.uuid4().hex
        self.pair(request_id=nonce)
        with self.assertRaises(ValueError):
            self.pair(request_id=nonce)
        pending = self.pair()
        with self.store.db() as db:
            db.execute('UPDATE pairings SET expires=0')
        with self.assertRaises(Denied):
            self.ceremony('pair', pending['approval_url'].split('/')[-1])

    def test_disconnected_request_cannot_be_created_or_approved(self):
        self.paired()
        # Simulate Runner passing pairing immediately before owner disconnects.
        self.store.paired(self.agent, self.public, RP)
        self.ceremony('unpair', self.agent)
        with self.assertRaises(Denied):
            self.store.inventory_request({'agent': self.agent, 'mode': 'persistent', 'lifetime': 3600})
        self.paired()
        req = self.store.inventory_request({'agent': self.agent, 'mode': 'persistent', 'lifetime': 3600})
        with self.store.db() as db:
            db.execute("UPDATE paired_agents SET status='revoked' WHERE id=?", (self.agent,))
        with self.assertRaises(Denied):
            self.ceremony('approve', req['request_id'])

    def test_pairing_is_bound_to_exact_public_key_label_and_request(self):
        pending = self.pair(); target = pending['approval_url'].split('/')[-1]
        start = self.passkeys.begin('owner-session', 'pair', target, admin='owner')
        with self.store.db() as db:
            db.execute("UPDATE pairings SET label='altered' WHERE id=?", (target,))
        with self.assertRaises(Denied):
            self.passkeys.finish('owner-session', start['ceremony_id'], self.owner.response(start), admin='owner')
        for op in ('pair', 'unpair', 'approve_pair'):
            with self.assertRaises(Denied):
                self.store.rpc(op, {})

    def test_inventory_format_withholds_unapproved_metadata_and_is_bounded(self):
        row = {'name': 'app-1', 'image': 'example/app:latest', 'state': 'running', 'project': 'existing-app',
               'service': 'web', 'environment': 'PRIVATE', 'mounts': '/volume1/private', 'labels': 'TOKEN=secret'}
        docker = Mock(return_value=json.dumps(row).encode())
        result = collect(docker)
        output = json.dumps(result)
        self.assertNotIn('PRIVATE', output); self.assertNotIn('/volume1', output); self.assertNotIn('TOKEN', output)
        self.assertEqual(result['containers'][0]['project'], 'existing-app')
        self.assertFalse(result['managed_access_granted'])
        self.assertEqual(docker.call_args.args[:2], ('ps', '--all'))
        result = collect(Mock(return_value=('\n'.join([json.dumps(row)]*65)).encode()))
        self.assertEqual(len(result['containers']), 64); self.assertTrue(result['truncated'])
        row.update(state='secret state', project='/volume1/private', image='https://user:password@host/image')
        output = json.dumps(collect(Mock(return_value=json.dumps(row).encode())))
        self.assertNotIn('password', output); self.assertNotIn('/volume1', output); self.assertNotIn('secret state', output)


class RunnerBoundary(unittest.TestCase):
    """Exercise signed wire requests at the real privileged dispatch boundary."""
    def setUp(self):
        projects.DurableTasks.setUp(self)
        self.store = Store(Path(self.temp.name) / 'auth.sqlite', ORIGIN)
        self.cfg['authorization'] = {'socket': '/run/auth.sock', 'service_key': '/etc/service.key',
                                     'agents': {'openclaw': '/etc/legacy.key'}}
        self.cfg['images']['example.invalid/team/app']['digests'] = ['a'*64]
        # NAS ships with provisioning disabled; inventory must be independent.
        self.cfg['enabled'] = False
        self.service = projects.Service('policy', self.runner)
        self.key = Ed25519PrivateKey.generate(); self.public = agents.public_key(self.key)
        self.agent = agents.identity(self.public)
        self.rpc = patch('deployer.service.rpc.call', side_effect=lambda cfg, op, val: self.store.rpc(op, val))
        self.rpc.start()

    def tearDown(self):
        self.rpc.stop(); projects.DurableTasks.tearDown(self)

    def wire(self, op, payload=None, **changes):
        value = {'version': 2, 'agent': self.agent, 'project': INVENTORY_PROJECT, 'operation': op,
                 'payload': payload or {}, 'public_key': self.public, 'audience': RP,
                 'request_id': uuid.uuid4().hex, 'timestamp': int(time.time()), **changes}
        raw = schema.canonical(value)
        return {'raw': raw, 'signature': agents.sign(raw.encode(), self.key)}

    def test_inventory_fails_closed_until_pair_and_separate_read_grant(self):
        with patch.object(self.service, 'docker', return_value=b'') as docker:
            with self.assertRaises(Denied):
                self.service.dispatch_wire(self.wire('inventory'))
            with self.store.db() as db:
                db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                           (self.agent,self.public,'test','owner',None,int(time.time()),'active'))
            with self.assertRaises(Denied):
                self.service.dispatch_wire(self.wire('inventory'))
            docker.assert_not_called()
            req = self.service.dispatch_wire(self.wire('inventory_request', {'mode':'persistent','lifetime':3600}))
            with self.store.db() as db:
                self.store.issue(db, req['request_id'], 'test-owner', None)
            self.assertEqual(self.service.dispatch_wire(self.wire('inventory'))['containers'], [])
            self.assertEqual(docker.call_count, 1)
            # Even with provisioning enabled, inventory permission alone cannot mutate.
            self.cfg['enabled'] = True
            for op in ('start', 'stop', 'restart', 'retire'):
                with self.assertRaises((Denied, ValueError)):
                    self.service.dispatch_wire(self.wire(op))
            self.assertEqual(docker.call_count, 1)


class GatewayBoundary(unittest.TestCase):
    def setUp(self):
        RunnerBoundary.setUp(self)

    def tearDown(self):
        RunnerBoundary.tearDown(self)

    wire = RunnerBoundary.wire

    def test_http_signatures_route_binding_replay_and_runner_inventory(self):
        with self.store.db() as db:
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       (self.agent,self.public,'test','owner',None,int(time.time()),'active'))
        req = self.store.inventory_request({'agent':self.agent,'mode':'persistent','lifetime':3600})
        with self.store.db() as db:
            self.store.issue(db, req['request_id'], 'test-owner', None)
        sockpath = str(Path(self.temp.name) / 'broker.sock')
        class Handler(gateway.Gateway):
            pass
        Handler.cfg = {'agents':{'openclaw':'/unused/static.key'},'nonce_db':str(Path(self.temp.name)/'gateway-nonces')}
        Handler.secret = b's'*48
        httpd = BoundedHTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=httpd.serve_forever); thread.start()
        stop = threading.Event()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as unix:
            unix.bind(sockpath); unix.listen(4); unix.settimeout(.1)
            def receive():
                while not stop.is_set():
                    try:
                        connection,_ = unix.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        wire = json.loads(protocol.read_frame(connection,131072))
                        try:
                            result = self.service.dispatch_wire(wire)
                        except (ValueError,Denied):
                            result = {'status':'denied'}
                        connection.sendall(schema.canonical(result).encode()+b'\n')
            listener = threading.Thread(target=receive); listener.start()
            def post(wire, route='/v2/inventory', host=RP):
                client = http.client.HTTPConnection('127.0.0.1',httpd.server_port,timeout=5)
                client.request('POST',route,wire['raw'].encode(),{'Host':host,
                    'X-Management-Signature':wire['signature'],'Content-Type':'application/json'})
                response=client.getresponse(); result=response.status,json.loads(response.read()); client.close()
                return result
            try:
                row = {'name':'legacy-web-1','project':'legacy','service':'web','state':'running','image':'example/web:latest'}
                with patch('deployer.service.SOCKET',sockpath), patch.object(self.service,'docker',return_value=json.dumps(row).encode()) as docker:
                    wire = self.wire('inventory')
                    code,result = post(wire)
                    self.assertEqual(code,200); self.assertEqual(result['containers'][0]['project'],'legacy')
                    self.assertEqual(post(wire)[1]['status'],'denied')
                    self.assertEqual(post(self.wire('inventory'),route='/v2/projects/restart')[0],403)
                    self.assertEqual(post(self.wire('inventory'),host='other.example.ts.net')[0],403)
                    forged = self.wire('inventory'); forged['signature']='ed25519='+'0'*128
                    self.assertEqual(post(forged)[0],403)
                    with self.store.db() as db:
                        db.execute("UPDATE paired_agents SET status='revoked'")
                    self.assertEqual(post(self.wire('inventory'))[1]['status'],'denied')
                    self.assertEqual(docker.call_count,1)
            finally:
                stop.set(); httpd.shutdown(); httpd.server_close(); thread.join(); listener.join(timeout=2)
            for op in ('start', 'stop', 'restart', 'retire'):
                with self.assertRaises((Denied, ValueError)):
                    self.service.dispatch_wire(self.wire(op))
            self.assertEqual(docker.call_count, 1)
