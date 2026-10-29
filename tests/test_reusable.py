import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from gateway.core import Gateway
from gateway.store import Store
from runner import boundary, execution
from runner.server import Runner
from shared.wire import Denied
from shared import preview


class Grants(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'db')
        self.store.pair('a', 'key', 'agent')
        with self.store.db() as db:
            db.execute("UPDATE agents SET status='active'")
        self.gateway = Gateway(self.store, '', 'https://example', 'example')
        self.identity = {'project': 'app', 'working_dir': '/volume1/docker/app',
                         'config_files': ['/volume1/docker/app/compose.yaml']}
        self.calls = []
        def runner(op, **args):
            self.calls.append((op, args))
            if op == 'plan':
                return {'identity': args['identity'], 'compose': args['compose_text'], 'base': {}}
            if op == 'authorize_boundary':
                return args['boundary']
            if op == 'projects':
                return {'projects': [], 'root': '/volume1/docker'}
            return {'status': 'success'}
        self.gateway.runner = runner

    def tearDown(self):
        for thread in self.gateway.threads:
            thread.join()
        self.temp.cleanup()

    def grant(self, scope, lifetime=None, boundary=None):
        with self.store.db() as db:
            gid = self.store.add_grant(db, 'a', '*' if scope == 'read' else 'app', self.identity,
                                       lifetime, 'r', scope, boundary)
        return self.store.grant('a', '*' if scope == 'read' else 'app', scope)

    def call(self, op, **args):
        return self.gateway.agent({'agent': 'a', 'public_key': 'key', 'op': op, 'args': args})

    def test_permanent_grants_and_idempotent_migration(self):
        self.grant('read')
        self.grant('manage')
        self.assertEqual(len(Store(self.store.path).grants('a')), 2)
        self.assertTrue(all(g['expires'] is None for g in self.store.grants('a')))

    def test_legacy_never_upgraded(self):
        self.grant('legacy', 100)
        self.assertIsNone(Store(self.store.path).grant('a', 'app', 'manage'))
        with self.assertRaises(Denied):
            self.call('projects')

    def test_explicit_global_self_read(self):
        with self.assertRaises(Denied):
            self.call('read', project='deployer')
        self.grant('read')
        self.call('read', project='deployer')
        self.assertEqual(self.calls[-1], ('diagnose', {'project': 'deployer'}))

    def test_repeated_changes_and_down_do_not_request_approval(self):
        self.grant('manage', boundary={'mounts': [], 'networks': []})
        for kind in ('change', 'change', 'down'):
            result = self.call('request', kind=kind, project='app', compose='services: {}')
            self.assertIn('job', result)
        for thread in self.gateway.threads:
            thread.join()
        self.assertFalse(self.store.dashboard()['requests'])
        self.assertEqual(len([c for c in self.calls if c[0] == 'apply']), 2)

    def test_finite_elevation_and_revocation_rechecked_in_job(self):
        manage = self.grant('manage')
        with self.assertRaises(Denied):
            self.grant('elevated')
        elevated = self.grant('elevated', 60, {'manage_grant': manage['id']})
        works = []
        self.gateway.job = lambda actor, project, op, work: works.append(work) or 'job'
        self.call('exec', project='app', container='a' * 64, argv=['echo', 'hello'])
        self.call('exec', project='app', container='a' * 64, argv=['echo', 'again'])
        works[0]()
        with self.store.db() as db:
            db.execute("UPDATE grants SET status='revoked' WHERE id=?", (elevated['id'],))
        with self.assertRaises(Denied):
            works[1]()
        self.grant('elevated', 1, {'manage_grant': manage['id']})
        with patch('gateway.store.now', return_value=int(time.time()) + 2):
            with self.assertRaises(Denied):
                self.call('exec', project='app', container='a' * 64, argv=['echo'])

    def test_preview_does_not_fall_back_to_legacy_diff(self):
        rid = self.store.create_request('a', 'app', 'change', {'plan': {
            'identity': self.identity, 'compose': 'secret-value', 'diff': 'secret-value',
            'env_set': {'TOKEN': 'secret-value'}}})
        text = json.dumps(self.gateway.public_preview(self.store.request(rid)))
        self.assertNotIn('secret-value', text)
        self.assertNotIn('secret-value', preview.diff({'services': {'web': {'command': 'secret-value'}}}, {}))

    def test_webhook_manage_revocation_and_payload_replay(self):
        import hashlib
        import hmac
        from shared.wire import canonical
        manage = self.grant('manage')
        config = {'repository_id': 1, 'branch': 'main', 'workflow': '.github/workflows/build.yml',
                  'manage_grant': manage['id'], 'agent': 'a'}
        with self.store.db() as db:
            db.execute('INSERT INTO triggers VALUES (?,?,?,?,?,?,?,?,?,?)',
                       ('t', 'app', 'web', canonical(config), canonical(self.identity), 'secret', None,
                        'active', 'r', int(time.time())))
        payload = canonical({'repository': {'id': 1}, 'action': 'completed', 'workflow_run': {
            'conclusion': 'success', 'head_branch': 'main', 'path': '.github/workflows/build.yml'}}).encode()
        signature = 'sha256=' + hmac.new(b'secret', payload, hashlib.sha256).hexdigest()
        self.assertTrue(self.gateway.webhook('t', payload, signature, 'workflow_run'))
        with self.assertRaises(Denied) as exc:
            self.gateway.webhook('t', payload, signature, 'workflow_run')
        self.assertEqual(exc.exception.code, 'replay')
        with self.store.db() as db:
            db.execute("UPDATE grants SET status='revoked' WHERE id=?", (manage['id'],))
        with patch('gateway.triggers.latest') as latest:
            self.gateway.check_triggers(force=True)
            latest.assert_not_called()
        self.assertEqual(self.store.dashboard()['triggers'][0]['last']['error'], 'not_authorized')


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.identity = {'project': 'app', 'working_dir': str(self.root / 'app'),
                         'config_files': [str(self.root / 'app/compose.yaml')]}
        self.boundary = {'mounts': [{'path': str(self.root), 'mode': 'ro'}], 'networks': []}

    def tearDown(self):
        self.temp.cleanup()

    def check(self, service=None, **extra):
        with patch('runner.compose.run', return_value=b''):
            return boundary.check({'services': {'web': service or {'image': 'busybox'}}, **extra},
                                  self.identity, self.boundary, '')

    def test_mount_ro_and_outside_and_symlink(self):
        mount = {'type': 'bind', 'source': str(self.root), 'target': '/data', 'read_only': True}
        self.check({'volumes': [mount]})
        for source, ro in [(str(self.root), False), ('/tmp', True)]:
            with self.assertRaises(Denied):
                self.check({'volumes': [{**mount, 'source': source, 'read_only': ro}]})
        (self.root / 'link').symlink_to('/etc')
        with self.assertRaises(Denied):
            self.check({'volumes': [{**mount, 'source': str(self.root / 'link')}]})

    def test_resource_and_host_escape_rejections(self):
        for service in [{'privileged': True}, {'network_mode': 'host'}, {'pid': 'container:foreign'},
                        {'ipc': 'service:foreign'}, {'devices': ['/dev/mem']}, {'post_start': [{'command': 'id'}]},
                        {'volumes_from': ['foreign']}, {'build': '.'}, {'cap_add': ['NET_ADMIN']}]:
            with self.subTest(service=service), self.assertRaises(Denied):
                self.check(service)
        for volumes in [{'data': {'external': True}}, {'data': {'name': 'foreign'}},
                        {'data': {'driver_opts': {'device': '/etc'}}}]:
            with self.assertRaises(Denied):
                self.check(volumes=volumes)
        with patch('runner.compose.run', side_effect=[b'app_data', b'[{"Labels":{"com.docker.compose.project":"foreign"}}]']):
            with self.assertRaises(Denied):
                boundary.check({'volumes': {'data': {}}}, self.identity, self.boundary, '')

    def test_external_network_requires_explicit_boundary(self):
        with self.assertRaises(Denied):
            self.check(networks={'edge': {'name': 'shared', 'external': True}})
        self.boundary['networks'] = ['shared']
        self.check(networks={'edge': {'name': 'shared', 'external': True}})

    def test_preflight_blocks_hidden_file_loading(self):
        for text in ['include: /etc/passwd', 'services: {web: {"env_file": /etc/passwd}}',
                     'services: {web: {extends: {file: ../other}}}', 'services: &alias {}',
                     'services: {web: {build: .}}']:
            with self.assertRaises(Denied):
                boundary.preflight(text)

    def test_exec_argv_validation(self):
        execution.validate(['sh', '-c', 'echo explicit shell'], 30)
        for argv in ['sh -c id', [], ['--privileged'], ['echo', chr(0)]]:
            with self.assertRaises(Denied):
                execution.validate(argv, 30)
        for timeout in [0, 121, True]:
            with self.assertRaises(Denied):
                execution.validate(['id'], timeout)

    def test_exec_target_and_expiry(self):
        wd = self.root / 'app'
        wd.mkdir()
        (wd / 'compose.yaml').write_text('services: {}')
        runner = Runner(self.root)
        target = {'Id': 'a' * 64, 'Config': {'Labels': {
            'com.docker.compose.project': 'app', 'com.docker.compose.project.working_dir': str(wd),
            'com.docker.compose.project.config_files': str(wd / 'compose.yaml')}}, 'HostConfig': {}}
        with patch.object(runner, 'check_boundary'), patch('runner.compose.observed_identity', return_value=self.identity),              patch('runner.diagnostics.inspect_project', return_value=[target]):
            with self.assertRaises(Denied) as exc:
                runner.exec(self.identity, self.boundary, 'b' * 64, ['id'], int(time.time()) + 60)
            self.assertEqual(exc.exception.code, 'target_mismatch')
            with self.assertRaises(Denied) as exc:
                runner.exec(self.identity, self.boundary, 'a' * 64, ['id'], int(time.time()) - 1)
            self.assertEqual(exc.exception.code, 'not_authorized')
