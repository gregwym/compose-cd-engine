import copy
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock
from deployer import adoption, ingress, schema
from shared.bounded import run
from authorization.scope import Denied
from test_pairing_inventory import PairingInventory, RunnerBoundary

CID = 'a' * 64


def row():
    return {'container_id': CID, 'name': '/existing_web', 'project': 'existing-app', 'service': 'web',
            'image': 'example.invalid/app:latest', 'image_id': 'sha256:' + 'b'*64,
            'working_dir': '/srv/existing', 'config_files': '/srv/existing/compose.yaml',
            'mounts': [{'Type': 'bind', 'Source': '/srv/data', 'Destination': '/data', 'RW': True,
                        'SecretExtra': 'DO_NOT_RETURN'}],
            'ports': {'8080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '18080'}]},
            'networks': ['existing_default', None], 'state': 'running'}


class Projection(unittest.TestCase):
    def docker(self, value=None, after=None):
        return Mock(side_effect=[CID.encode(), json.dumps(value or row()).encode(),
                                 (after if after is not None else CID).encode()])

    def test_structure_is_explicit_and_preview_cannot_execute(self):
        docker = self.docker()
        result = adoption.inspect_project(docker, 'existing-app')
        self.assertNotIn('DO_NOT_RETURN', json.dumps(result))
        self.assertNotIn('.Config.Env', adoption.FORMAT)
        self.assertFalse(result['adoption_ready'])
        self.assertFalse(adoption.adoption_preview(result)['execute_allowed'])
        result['containers'][0]['image_id'] = 'changed'
        with self.assertRaises(ValueError): adoption.adoption_preview(result)
        self.assertTrue(all(c.args[0] in ('ps', 'inspect') for c in docker.call_args_list))

    def test_total_deadline_propagated_and_delayed_query_fails(self):
        import time
        calls = []
        def delayed(*args, timeout):
            calls.append(timeout)
            time.sleep(.02)
            return CID.encode()
        with self.assertRaises(Denied): adoption.inspect_project(delayed, 'existing-app', budget=.01)
        self.assertEqual(len(calls), 1)
        self.assertLessEqual(calls[0], .01)

    def test_cross_project_and_membership_drift_fail(self):
        changed = row(); changed['project'] = 'other'
        with self.assertRaises(Denied): adoption.inspect_project(self.docker(changed), 'existing-app')
        with self.assertRaises(Denied): adoption.inspect_project(self.docker(after='c'*64), 'existing-app')
        with self.assertRaises(Denied): adoption.inspect_project(Mock(return_value=b''), 'existing-app')

    def test_no_unknown_top_level_fields_or_relative_paths(self):
        for key, value in [('environment', 'SECRET'), ('working_dir', '../private')]:
            changed = row(); changed[key] = value
            with self.assertRaises(ValueError): adoption.inspect_project(self.docker(changed), 'existing-app')
        with self.assertRaises(ValueError): adoption.inspection_scope('--host=evil')


class InspectionGrants(PairingInventory):
    def test_inventory_does_not_grant_inspection_and_project_binding(self):
        self.paired(); self.grant()
        with self.assertRaises(Denied): self.store.rpc('inspect_access', {'agent': self.agent, 'project': 'existing-app'})
        request = self.store.rpc('inspect_request', {'agent': self.agent, 'project': 'existing-app',
                                                    'mode': 'once', 'lifetime': 600})
        self.ceremony('approve', request['request_id'])
        with self.assertRaises(Denied): self.store.rpc('inspect_access', {'agent': self.agent, 'project': 'other'})
        self.assertEqual(self.store.rpc('inspect_access', {'agent': self.agent, 'project': 'existing-app'})['status'], 'authorized')
        with self.assertRaises(Denied): self.store.rpc('inspect_access', {'agent': self.agent, 'project': 'existing-app'})


class InspectionWire(RunnerBoundary):
    def test_failed_once_inspection_cannot_be_replayed(self):
        with self.store.db() as db:
            import time
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       (self.agent,self.public,'test','owner',None,int(time.time()),'active'))
        req=self.service.dispatch_wire(self.wire('inspect_request',{'mode':'once','lifetime':600},project='existing-app'))
        with self.store.db() as db:self.store.issue(db,req['request_id'],'owner',None)
        from unittest.mock import patch
        with patch('deployer.adoption.inspect_project',side_effect=TimeoutError('slow')) as observer:
            with self.assertRaises(TimeoutError):self.service.dispatch_wire(self.wire('inspect',project='existing-app'))
            with self.assertRaises(Denied):self.service.dispatch_wire(self.wire('inspect',project='existing-app'))
            self.assertEqual(observer.call_count,1)

    def test_empty_legacy_agents_and_separate_grant_before_docker(self):
        self.cfg['authorization']['agents'] = {}
        schema.policy(self.cfg)
        with self.store.db() as db:
            import time
            db.execute('INSERT INTO paired_agents VALUES (?,?,?,?,?,?,?)',
                       (self.agent,self.public,'test','owner',None,int(time.time()),'active'))
        with self.assertRaises(Denied):
            self.service.dispatch_wire(self.wire('inspect', project='existing-app'))
        req = self.service.dispatch_wire(self.wire('inspect_request', {'mode':'persistent','lifetime':600}, project='existing-app'))
        with self.store.db() as db: self.store.issue(db, req['request_id'], 'owner', None)
        docker = Mock(side_effect=[CID.encode(), json.dumps(row()).encode(), CID.encode()])
        self.service.docker = docker
        result = self.service.dispatch_wire(self.wire('inspect', project='existing-app'))
        self.assertFalse(result['managed_access_granted'])


class IngressPlans(unittest.TestCase):
    def baseline(self):
        return {'TCP': {'443': {'HTTPS': True}, '8443': {'HTTPS': True}},
                'Web': {'apps.example.ts.net:443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:18793'}}}},
                'AllowFunnel': {}}

    def plan(self, current=None, **kwargs):
        return ingress.plan(current or self.baseline(), **{'hostname': 'apps.example.ts.net', 'port': 9443,
                    'upstream': 'http://127.0.0.1:8080', 'allowed_upstreams': ['http://127.0.0.1:8080'], **kwargs})

    def test_merge_preserves_control_plane_and_reconciles_drift(self):
        baseline = self.baseline(); original = copy.deepcopy(baseline)
        planned = self.plan(baseline)
        self.assertEqual(baseline, original)
        self.assertEqual(planned['candidate']['Web']['apps.example.ts.net:443'], baseline['Web']['apps.example.ts.net:443'])
        self.assertFalse(planned['execute_allowed'])
        ingress.reconcile(planned, baseline, allowed_upstreams=['http://127.0.0.1:8080'])
        baseline['TCP']['10000'] = {'HTTPS': True}
        with self.assertRaises(Denied): ingress.reconcile(planned, baseline, allowed_upstreams=['http://127.0.0.1:8080'])

    def test_rehashed_candidate_tampering_is_not_authority(self):
        baseline = self.baseline()
        for change in ('control', 'funnel'):
            candidate = self.plan()
            if change == 'control': candidate['candidate']['TCP']['443'] = {'TCPForward': 'bad:1'}
            else: candidate['candidate']['AllowFunnel']['apps.example.ts.net:9443'] = True
            candidate['candidate_hash'] = schema.fingerprint(candidate['candidate'])
            with self.assertRaises(Denied):
                ingress.reconcile(candidate, baseline, allowed_upstreams=['http://127.0.0.1:8080'])

    def test_reserved_ports_upstreams_public_and_conflict_rejected(self):
        for port in (443, 8443):
            with self.assertRaises((ValueError, Denied)): self.plan(port=port)
        for upstream in ('http://127.0.0.1:18792', 'http://192.168.1.1:8080', 'http://user:secret@127.0.0.1:8080'):
            with self.assertRaises(Denied): self.plan(upstream=upstream, allowed_upstreams=[upstream])
        baseline = self.baseline(); baseline['AllowFunnel']['apps.example.ts.net:443'] = True
        with self.assertRaises(Denied): self.plan(baseline)
        planned = self.plan()
        with self.assertRaises(Denied): self.plan(planned['candidate'])


class BoundedProcess(unittest.TestCase):
    def test_success_overflow_timeout_and_nonzero(self):
        self.assertEqual(run([sys.executable, '-c', 'print("ok")'], env=os.environ), b'ok\n')
        with self.assertRaises(ValueError): run([sys.executable, '-c', 'print("x"*1000000)'], env=os.environ, limit=100)
        with self.assertRaises(subprocess.TimeoutExpired): run([sys.executable, '-c', 'import time; time.sleep(5)'], env=os.environ, timeout=.05)
        with self.assertRaises(subprocess.CalledProcessError): run([sys.executable, '-c', 'raise SystemExit(2)'], env=os.environ)
