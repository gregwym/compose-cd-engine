import copy
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deployer import schema
from deployer.service import Service
from management import protocol

IMAGE = 'example.invalid/team/app@sha256:' + 'a' * 64


def policy(root='/srv/pilot'):
    return {'workspace': root + '/private', 'storage': {
        'config': {'path': root + '/config', 'shared': False, 'uid': 10001, 'gid': 10001},
        'downloads': {'path': root + '/downloads', 'shared': True, 'uid': 10001, 'gid': 10001}},
        'images': {'example.invalid/team/app': {'digests': [], 'allow_unsigned': True,
                   'healthcheck': ['/bin/true'], 'environment': ['TOKEN', 'TZ']}},
        'port_range': [20000, 20010], 'bind_ip': '192.168.10.2', 'max_projects': 3,
        'max_services': 4, 'max_memory_mb': 512, 'max_cpus': 4, 'max_pids': 64,
        'health_timeout': 10, 'enabled': True, 'allow_egress': True, 'operations': sorted(schema.OPS)}


def spec():
    return {'services': {'app': {'image': IMAGE, 'memory_mb': 64, 'cpus': 1,
        'environment': {'TOKEN': 'PRIVATE-${HOST_SECRET}-$$'},
        'mounts': [{'storage': 'config', 'slot': 'app', 'target': '/app/config', 'read_only': False}],
        'ports': [{'published': 20000, 'target': 8080, 'protocol': 'tcp'}]}}}


def message(op, payload=None, project='test'):
    return {'project': project, 'operation': op, 'payload': payload or {},
            'request_id': uuid.uuid4().hex, 'timestamp': int(time.time())}


class DeclarationBoundary(unittest.TestCase):
    def test_generated_compose_and_preview_never_return_secret_or_host_paths(self):
        compose, budget = schema.compile_project('test', spec(), schema.policy(policy()))
        app = compose['services']['app']
        self.assertEqual(app['cap_drop'], ['ALL'])
        self.assertEqual(app['environment']['TOKEN'], 'PRIVATE-$${HOST_SECRET}-$$$$')
        self.assertEqual(app['volumes'][0]['source'], '/srv/pilot/config/test/app')
        preview = json.dumps(schema.preview(spec()))
        self.assertNotIn('PRIVATE', preview)
        self.assertNotIn('/srv', preview)

    def test_all_unrecognized_compose_capabilities_rejected(self):
        for key in ('privileged', 'build', 'provider', 'include', 'extends', 'env_file', 'label_file',
                    'command', 'entrypoint', 'network_mode', 'pid', 'devices', 'cap_add', 'volumes',
                    'post_start', 'pre_stop', 'use_api_socket', 'secrets', 'container_name'):
            item = spec()
            item['services']['app'][key] = 'attacker'
            with self.subTest(key=key), self.assertRaises(ValueError):
                schema.compile_project('test', item, policy())
        item = spec()
        item['include'] = '/private'
        with self.assertRaises(ValueError):
            schema.compile_project('test', item, policy())

    def test_path_escape_unknown_storage_and_device_mount_rejected(self):
        for key, value in [('storage', 'unknown'), ('slot', '../private'), ('target', '/dev'),
                           ('target', '/app/../run/docker.sock')]:
            item = spec()
            item['services']['app']['mounts'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                schema.compile_project('test', item, policy())
        with self.assertRaises(ValueError):
            schema.compile_project('../escape', spec(), policy())

    def test_mutable_unapproved_images_environment_and_resource_limits_rejected(self):
        for key, value in [('image', 'example.invalid/team/app:latest'),
                           ('image', IMAGE.replace('team/app', 'evil/app')),
                           ('memory_mb', 513), ('cpus', True), ('environment', {'UNAPPROVED': 'value'})]:
            item = spec()
            item['services']['app'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                schema.compile_project('test', item, policy())
        cfg = policy()
        cfg['images']['example.invalid/team/app']['digests'] = ['b' * 64]
        with self.assertRaises(ValueError):
            schema.compile_project('test', spec(), cfg)

    def test_policy_overlaps_unsigned_defaults_and_bad_binding_rejected(self):
        for mutate in [lambda p: p['storage']['config'].update(path=p['workspace'] + '/files'),
                       lambda p: p.update(bind_ip='0.0.0.0'),
                       lambda p: p.update(bind_ip='127.0.0.1'),
                       lambda p: p['images']['example.invalid/team/app'].update(allow_unsigned=False)]:
            cfg = policy()
            mutate(cfg)
            with self.assertRaises(ValueError):
                schema.policy(cfg)

    def test_new_envelope_cannot_cross_old_authentication_boundary(self):
        value = message('plan', spec())
        raw = json.dumps(value).encode()
        with self.assertRaises(ValueError):
            protocol.request(raw)
        self.assertEqual(schema.request(raw), value)


class DurableTasks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.cfg = policy(str(root))
        for key in ('private', 'config', 'downloads', 'state'):
            (root / key).mkdir(mode=0o700)
        self.runner = SimpleNamespace(STATE_DIR=root / 'state', DOCKER='/fixed/docker',
                                     write_json=lambda p, v: p.write_text(json.dumps(v)))
        self.trust = patch('deployer.service.trusted_json', side_effect=lambda _: copy.deepcopy(self.cfg))
        self.trust.start()
        self.directories = patch('deployer.service.protected_directory', side_effect=Path)
        self.directories.start()
        self.service = Service('policy', self.runner)

    def tearDown(self):
        self.trust.stop()
        self.directories.stop()
        self.temp.cleanup()

    def plan(self, item=None, project='test'):
        return self.service.dispatch(message('plan', spec() if item is None else item, project))['plan_id']

    def apply(self, plan=None, project='test'):
        return self.service.dispatch(message('apply', {'plan_id': plan or self.plan(project=project)}, project))['task_id']

    def task(self, task):
        return self.service.dispatch(message('task', {'task_id': task}))

    def run_job(self, failure=None):
        with patch.object(self.service, 'docker', return_value=b''), \
             patch.object(self.service, 'provision_storage'), \
             patch.object(self.service, 'verify_healthchecks'), \
             patch.object(self.service, 'ready'), \
             patch.object(self.service, 'compose', side_effect=failure):
            self.service.run_one()

    def test_compose_success_cannot_hide_wrong_runtime_readiness_probe(self):
        task = self.apply()
        with patch.object(self.service, 'docker', side_effect=[b'', b'', b'id', b'["CMD","/bin/false"]']), \
             patch.object(self.service, 'provision_storage'), patch.object(self.service, 'compose'):
            self.service.run_one()
        result = self.task(task)
        self.assertEqual(result['status'], 'recovery_required')
        self.assertEqual(result['category'], 'readiness_configuration_mismatch')

    def test_apply_is_idempotent_beyond_request_nonce(self):
        plan = self.plan()
        task = self.apply(plan)
        self.assertEqual(self.apply(plan), task)
        with self.service.lock():
            self.assertEqual(self.apply(plan), task)
        self.run_job()
        self.assertEqual(self.apply(plan), task)
        self.assertEqual(self.task(task)['status'], 'success')
        with self.service.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM tasks').fetchone()[0], 1)

    def test_policy_change_and_expired_plan_rejected_before_docker(self):
        plan = self.plan()
        self.cfg['max_pids'] += 1
        with self.assertRaises(ValueError):
            self.apply(plan)
        self.cfg['max_pids'] -= 1
        with self.service.db() as db:
            db.execute('UPDATE plans SET created=0')
        with self.assertRaises(ValueError):
            self.apply(plan)

    def test_global_port_and_memory_reservations_reject_other_project(self):
        self.apply()
        with self.assertRaises(ValueError):
            self.plan(project='other')
        item = spec()
        item['services']['app']['ports'] = []
        item['services']['app']['memory_mb'] = 512
        with self.assertRaises(ValueError):
            self.plan(item, project='other')

    def test_worker_rechecks_resources_after_preceding_update_failed(self):
        task = self.apply()
        item = spec()
        item['services']['app']['ports'] = []
        item['services']['app']['memory_mb'] = 512
        with self.service.db() as db:
            db.execute('INSERT INTO projects VALUES (?,1,?,0)', ('other', json.dumps(item)))
        with patch.object(self.service, 'compose', side_effect=AssertionError('Docker touched')) as compose:
            self.service.run_one()
            compose.assert_not_called()
        self.assertEqual(self.task(task)['status'], 'failed')

    def test_task_lookup_is_project_scoped_and_has_no_spec(self):
        task = self.apply()
        with self.assertRaises(ValueError):
            self.service.dispatch(message('task', {'task_id': task}, 'other'))
        self.assertNotIn('PRIVATE', json.dumps(self.task(task)))

    def test_failure_before_mutation_does_not_claim_rollback_or_latch_recovery(self):
        task = self.apply()
        self.run_job(RuntimeError('PRIVATE /host/path'))
        self.assertEqual(self.task(task)['status'], 'failed')
        self.assertNotIn('PRIVATE', json.dumps(self.task(task)))
        with self.service.db() as db:
            self.assertEqual(db.execute('SELECT recovery FROM projects').fetchone()[0], 0)

    def test_partial_failure_latches_recovery_before_mutation(self):
        task = self.apply()
        def command(*args, **kwargs):
            if 'up' in args:
                with self.service.db() as db:
                    self.assertEqual(db.execute('SELECT recovery FROM projects').fetchone()[0], 1)
                raise RuntimeError('PRIVATE')
        self.run_job(command)
        self.assertEqual(self.task(task)['status'], 'recovery_required')
        for op in ('start', 'restart'):
            with self.assertRaises(ValueError):
                self.service.dispatch(message(op))
        # Fresh plan cannot bypass recovery; replay returns the original task.
        with self.assertRaises(ValueError):
            self.apply(self.plan())

    def test_crash_recovery_does_not_replay_running_tasks(self):
        task = self.apply()
        with self.service.db() as db:
            db.execute("UPDATE tasks SET state='running'")
        restored = Service('policy', self.runner)
        with restored.db() as db:
            self.assertEqual(db.execute('SELECT state FROM tasks').fetchone()[0], 'outcome_unknown')
            self.assertEqual(db.execute('SELECT recovery FROM projects').fetchone()[0], 1)
        self.assertFalse(restored.run_one())

    def test_worker_rechecks_policy_even_after_task_accepted(self):
        task = self.apply()
        self.cfg['enabled'] = False
        self.run_job()
        self.assertEqual(self.task(task)['status'], 'failed')

    def test_privileged_operation_allowlist_cannot_be_bypassed(self):
        self.cfg['operations'] = ['status', 'task']
        with self.assertRaises(ValueError):
            self.plan()

    def test_http_large_signed_declaration_roundtrip_and_route_replay_rejection(self):
        import hashlib
        import hmac
        import http.client
        import socket
        import threading
        from management.gateway import Gateway
        from receiver.receiver import BoundedHTTPServer
        path = str(Path(self.temp.name) / 'broker.sock')
        class Handler(Gateway):
            secret = b'x' * 48
            cfg = {'projects': {}, 'deployer': {'operations': ['plan']},
                   'nonce_db': str(Path(self.temp.name) / 'gateway-nonces.sqlite')}
        server = BoundedHTTPServer(('127.0.0.1', 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
            unix.bind(path)
            unix.listen(1)
            def receive():
                connection, _ = unix.accept()
                with connection:
                    value = schema.request(protocol.read_frame(connection, schema.MAX_REQUEST))
                    result = self.service.dispatch(value)
                    connection.sendall(json.dumps(result).encode() + b'\n')
            receiver = threading.Thread(target=receive)
            receiver.start()
            server_thread.start()
            try:
                item = spec()
                item['services']['app']['environment']['TOKEN'] = 'SECRET' * 500
                value = message('plan', item)
                raw = json.dumps(value).encode()
                self.assertGreater(len(raw), protocol.MAX_REQUEST)
                signature = 'sha256=' + hmac.new(Handler.secret, raw, hashlib.sha256).hexdigest()
                def post(route):
                    client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                    client.request('POST', route, raw, {'X-Management-Signature': signature})
                    response = client.getresponse()
                    code, body = response.status, response.read()
                    client.close()
                    return code, json.loads(body)
                with patch('deployer.service.SOCKET', path):
                    code, body = post('/v1/projects')
                    self.assertEqual(code, 200)
                    self.assertEqual(body['status'], 'planned')
                    self.assertNotIn('SECRET', json.dumps(body))
                    self.assertEqual(post('/v1/projects')[0], 403)
                    self.assertEqual(post('/v1/manage')[0], 403)
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)
                receiver.join(timeout=5)

    def test_stale_revision_and_service_removal_rejected(self):
        old = self.plan()
        task = self.apply()
        self.run_job()
        with self.assertRaises(ValueError):
            self.apply(old)
        item = spec()
        item['services']['renamed'] = item['services'].pop('app')
        with self.assertRaises(ValueError):
            self.plan(item)

    def test_durable_queue_survives_restart(self):
        task = self.apply()
        restored = Service('policy', self.runner)
        with restored.db() as db:
            self.assertEqual(db.execute('SELECT state FROM tasks WHERE id=?', (task,)).fetchone()[0], 'queued')

    def test_symlink_slot_is_rejected_without_traversing_app_contents(self):
        root = Path(self.cfg['storage']['config']['path'])
        (root / 'test').mkdir()
        (root / 'test' / 'app').symlink_to(self.temp.name, target_is_directory=True)
        # Test this syscall boundary without requiring the test account to be root.
        original_fstat = os.fstat
        def owned(fd):
            actual = original_fstat(fd)
            return SimpleNamespace(st_uid=0, st_mode=actual.st_mode)
        with patch('deployer.service.os.fstat', side_effect=owned), self.assertRaises(ValueError):
            self.service.provision_storage('test', spec(), self.cfg)

    def test_existing_app_leaf_is_not_opened_or_traversed(self):
        root = Path(self.cfg['storage']['config']['path'])
        (root / 'test').mkdir()
        leaf = root / 'test' / 'app'
        leaf.mkdir(mode=0o750)
        original_open, original_stat, original_fstat = os.open, os.stat, os.fstat
        def open_parent(path, *args, **kwargs):
            self.assertNotEqual(path, 'app', 'existing app leaf must not be opened')
            return original_open(path, *args, **kwargs)
        def owned(fd):
            st = original_fstat(fd)
            return SimpleNamespace(st_uid=0, st_mode=st.st_mode)
        def app_stat(path, *args, **kwargs):
            st = original_stat(path, *args, **kwargs)
            if path == 'app':
                self.assertFalse(kwargs['follow_symlinks'])
                return SimpleNamespace(st_uid=10001, st_mode=st.st_mode)
            return st
        with patch('deployer.service.os.open', side_effect=open_parent), \
             patch('deployer.service.os.stat', side_effect=app_stat), \
             patch('deployer.service.os.fstat', side_effect=owned):
            self.service.provision_storage('test', spec(), self.cfg)
