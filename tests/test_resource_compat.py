import io
import json
import unittest
from unittest.mock import patch
from client import cdctl
from runner import boundary, diagnostics
from shared.wire import Denied
from test_reusable import Grants


class ReadPriority(Grants):
    def test_global_read_does_not_shadow_project_grants(self):
        self.grant('read')
        for scope in ('legacy', 'manage'):
            with self.subTest(scope=scope):
                self.grant(scope, 60)
                self.call('read', project='app')
                self.assertEqual(self.calls[-1], ('read', {'identity': self.identity}))
        self.call('read', project='deployer')
        self.assertEqual(self.calls[-1], ('diagnose', {'project': 'deployer'}))
        with self.store.db() as db:
            db.execute("UPDATE grants SET status='revoked' WHERE project='app'")
        self.call('read', project='app')
        self.assertEqual(self.calls[-1], ('diagnose', {'project': 'app'}))


for _name in list(vars(Grants)):
    if _name.startswith('test_'):
        setattr(ReadPriority, _name, None)
del Grants


class ResourceCompatibility(unittest.TestCase):
    CTX = boundary.Scope('app', '/volume1/docker/app', '/volume1/docker/deployer', ('/volume1/docker',), {'compose-deployer'})

    def check(self, kind='volumes', name='custom-state', owner='app', driver='local', options=None,
              exists=True, external=False, allowed=None):
        resource = {'Name': name, 'Driver': driver, 'Options': options,
                    'Labels': {'com.docker.compose.project': owner} if owner else {}}
        with patch('runner.boundary.inspect', return_value=resource if exists else None):
            return boundary.check({kind: {'state': {'name': name, 'external': external}}},
                                  {'project': 'app'}, {'mounts': [], 'networks': [], **(allowed or {})}, self.CTX)

    def test_own_volumes_are_the_projects_business(self):
        self.check()
        self.check(exists=False)  # Compose creates it with this project's label
        self.check(options={'type': 'tmpfs', 'device': 'tmpfs', 'o': 'size=64m'})
        self.check(owner='app', external=True)

    def test_foreign_unowned_volumes_need_the_boundary(self):
        for override in ({'owner': 'foreign'}, {'owner': None}, {'owner': 'foreign', 'external': True}):
            with self.subTest(override=override):
                with self.assertRaises(Denied) as exc:
                    self.check(**override)
                self.assertEqual(exc.exception.code, 'boundary_exceeded')
                self.check(**override, allowed={'volumes': ['custom-state']})

    def test_host_level_drivers_need_the_boundary(self):
        for override, feature in (({'driver': 'nfs'}, 'volume_driver:nfs'),
                                  ({'options': {'type': 'nfs', 'o': 'addr=nas', 'device': ':/x'}}, 'volume_mount:nfs')):
            with self.subTest(override=override):
                with self.assertRaises(Denied):
                    self.check(**override)
                self.check(**override, allowed={'host': [feature]})

    def test_bind_volume_device_is_a_host_path(self):
        with self.assertRaises(Denied) as exc:
            self.check(options={'device': '/etc', 'type': 'none', 'o': 'bind'})
        self.assertEqual(exc.exception.code, 'policy')

    def test_deployer_resources_are_never_reachable(self):
        for kind in ('volumes', 'networks'):
            with self.subTest(kind=kind), self.assertRaises(Denied) as exc:
                self.check(kind=kind, owner='compose-deployer', driver='bridge' if kind == 'networks' else 'local',
                           external=True, allowed={'networks': ['custom-state'], 'volumes': ['custom-state']})
            self.assertEqual(exc.exception.code, 'policy')

    def test_bridge_networks(self):
        self.check(kind='networks', driver='bridge')
        with self.assertRaises(Denied):
            self.check(kind='networks', driver='macvlan', options={'parent': 'eth0'})
        self.check(kind='networks', driver='macvlan', allowed={'host': ['network_driver:macvlan']})

    def test_namespaces_inside_the_project_are_allowed(self):
        config = {'services': {'proxy': {'network_mode': 'service:tailscale'}, 'tailscale': {}}}
        with patch('runner.boundary.inspect', return_value=None):
            boundary.check(config, {'project': 'app'}, {'mounts': [], 'networks': []}, self.CTX)
        for owner in ('foreign', 'compose-deployer'):
            labels = {'Config': {'Labels': {'com.docker.compose.project': owner}}}
            with self.subTest(owner=owner), patch('runner.boundary.inspect', return_value=labels), \
                    self.assertRaises(Denied):
                boundary.check({'services': {'proxy': {'network_mode': 'container:x'}}}, {'project': 'app'},
                               {'mounts': [], 'networks': []}, self.CTX)


class DiagnosticProjection(unittest.TestCase):
    def test_structural_network_mount_and_ownership_without_secrets(self):
        labels = {'com.docker.compose.project': 'app', 'com.docker.compose.service': 'web',
                  'com.docker.compose.project.working_dir': '/volume1/docker/app',
                  'com.docker.compose.project.config_files': '/volume1/docker/app/compose.yaml',
                  'secret-label': 'SECRET'}
        raw = [{'Id': 'cid', 'Name': '/app-web', 'Image': 'sha256:image',
                'Config': {'Image': 'image:tag', 'Labels': labels, 'Env': ['TOKEN=SECRET'], 'Cmd': ['SECRET']},
                'Mounts': [{'Type': 'bind', 'Source': '/volume1/media', 'Destination': '/media', 'RW': False},
                           {'Type': 'volume', 'Name': 'custom-state', 'Destination': '/state'}],
                'NetworkSettings': {'Networks': {'edge': {'NetworkID': 'nid', 'IPAddress': '172.20.0.2',
                                                         'Gateway': '172.20.0.1', 'DriverOpts': {'token': 'SECRET'}}}}}]
        network = {'Name': 'edge', 'Driver': 'bridge', 'Labels': labels, 'Options': {'token': 'SECRET'},
                   'IPAM': {'Driver': 'default', 'Options': {'token': 'SECRET'},
                            'Config': [{'Subnet': '172.20.0.0/16', 'Gateway': '172.20.0.1', 'secret': 'SECRET'}]}}
        volume = {'Name': 'custom-state', 'Driver': 'local', 'Labels': labels, 'Options': {'token': 'SECRET'}}
        image = {'Id': 'sha256:image', 'Config': {'Env': ['TOKEN=SECRET']}}
        with patch('runner.diagnostics.inspect_project', return_value=raw), patch('runner.compose.run',
                side_effect=[json.dumps([x]).encode() for x in (network, volume, image)]):
            result = diagnostics.diagnose('app')
        container = result['containers'][0]
        self.assertEqual(container['mounts'][0]['Source'], '/volume1/media')
        self.assertFalse(container['mounts'][0]['RW'])
        self.assertEqual(container['image_id'], 'sha256:image')
        self.assertEqual(container['ownership']['com.docker.compose.project'], 'app')
        self.assertEqual(container['network_endpoints']['edge']['IPAddress'], '172.20.0.2')
        self.assertEqual(result['networks'][0]['IPAM']['Config'][0]['Subnet'], '172.20.0.0/16')
        self.assertEqual(result['volumes'][0]['Labels']['com.docker.compose.project'], 'app')
        self.assertTrue(result['volumes'][0]['has_driver_options'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('secret-label', json.dumps(result))


class ClientReadDefault(unittest.TestCase):
    def test_request_read_defaults_to_environment(self):
        with patch('client.cdctl.Client') as client, patch('sys.stdout', new_callable=io.StringIO):
            client.return_value.call.return_value = {}
            cdctl.main(['request', 'read', '--permanent'])
            self.assertEqual(client.return_value.call.call_args.kwargs['project'], '*')
            cdctl.main(['request', 'read', 'explicit'])
            self.assertEqual(client.return_value.call.call_args.kwargs['project'], 'explicit')
            cdctl.main(['request', 'unserve', '--https-port', '8444'])
            self.assertEqual(client.return_value.call.call_args.kwargs['project'], '')


class ExecLiveCheck(unittest.TestCase):
    def test_default_cgroup_namespace_allowed_and_takeover_refused(self):
        import tempfile
        import time
        from pathlib import Path
        from runner.server import Runner
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / 'app').mkdir()
            (root / 'app/compose.yaml').write_text('services: {}')
            identity = {'project': 'app', 'working_dir': str(root / 'app'), 'config_files': [str(root / 'app/compose.yaml')]}
            labels = {'com.docker.compose.project': 'app', 'com.docker.compose.project.working_dir': identity['working_dir'],
                      'com.docker.compose.project.config_files': identity['config_files'][0]}
            runner = Runner(root)
            for host, mounts, allowed in (({'CgroupnsMode': 'host', 'IpcMode': 'private', 'CapAdd': ['NET_ADMIN']}, [], True),
                                          ({'Privileged': True}, [], False), ({'PidMode': 'host'}, [], False),
                                          ({}, [{'Type': 'bind', 'Source': '/var/run/docker.sock'}], False)):
                target = {'Id': 'a' * 64, 'Config': {'Labels': labels}, 'HostConfig': host, 'Mounts': mounts}
                with self.subTest(host=host, mounts=mounts), \
                        patch('runner.compose.observed_identity', return_value=identity), \
                        patch('runner.diagnostics.inspect_project', return_value=[target]), \
                        patch('runner.execution.run', return_value={'status': 'success', 'output': ''}) as run:
                    call = lambda: runner.exec(identity, {}, 'a' * 64, ['id'], int(time.time()) + 60, authorize=lambda: None)
                    if allowed:
                        call()
                        run.assert_called_once()
                    else:
                        with self.assertRaises(Denied) as exc:
                            call()
                        self.assertEqual(exc.exception.code, 'policy')


class ManageApproval(unittest.TestCase):
    def test_request_derives_and_approval_stores_what_was_shown(self):
        from test_reusable import Grants
        case = Grants('test_permanent_grants_and_idempotent_migration')
        case.setUp()
        try:
            original = case.gateway.runner
            def runner(op, **args):
                if op == 'projects':
                    return {'root': '/volume1/docker', 'projects': [{'project': 'app', 'identity': case.identity,
                                                                    'manageable': True, 'reason': None, 'services': []}]}
                if op == 'authorize_boundary' and args.get('derive', True):
                    case.calls.append((op, args))
                    return {'mounts': [{'path': '/volume1/download/bangumi', 'mode': 'rw'}], 'networks': [],
                            'volumes': [], 'host': []}
                return original(op, **args)
            case.gateway.runner = runner
            request = case.call('request', kind='manage', project='app', permanent=True, compose='services: {}')
            self.assertEqual(case.calls[-1][1]['compose_text'], 'services: {}')
            item = case.store.request(request['id'])
            case.gateway.perform(item)
            self.assertEqual(case.calls[-1], ('authorize_boundary', {
                'identity': case.identity, 'boundary': item['detail']['boundary'], 'new': False, 'derive': False}))
            self.assertEqual(case.store.grant('a', 'app', 'manage')['boundary']['mounts'][0]['path'], '/volume1/download/bangumi')
        finally:
            case.tearDown()
